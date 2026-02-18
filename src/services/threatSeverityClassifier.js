/**
 * Threat Severity Classifier
 * Classifies detected threats by severity and provides recommended response actions
 */

class ThreatSeverityClassifier {
  constructor() {
    // Severity levels
    this.SEVERITY_LEVELS = {
      CRITICAL: 'critical',
      HIGH: 'high',
      MEDIUM: 'medium',
      LOW: 'low',
      INFO: 'info'
    };

    // Threat characteristics
    this.threatCharacteristics = {
      ransomware: {
        baseScore: 0.95,
        factors: ['fileEncryption', 'extensionChanges', 'highFileActivity'],
        impact: 'System holds files hostage. Immediate response required.'
      },
      rootkit: {
        baseScore: 0.92,
        factors: ['kernelAccess', 'processMasking', 'registryHiding'],
        impact: 'Persistent system compromise. Deep forensics needed.'
      },
      botnet: {
        baseScore: 0.85,
        factors: ['commandControl', 'networkBeaconing', 'massReplication'],
        impact: 'System compromised for external control and attacks.'
      },
      trojan: {
        baseScore: 0.80,
        factors: ['backdoor', 'dataTheft', 'maliciousPayload'],
        impact: 'Backdoor access established. Data at risk.'
      },
      spyware: {
        baseScore: 0.75,
        factors: ['keylogging', 'screenCapture', 'networkMonitoring'],
        impact: 'Personal data and activities being monitored.'
      },
      adware: {
        baseScore: 0.55,
        factors: ['intrusiveAds', 'dataCollection', 'performanceDegradation'],
        impact: 'System performance impacted, privacy compromised.'
      },
      pup: {
        baseScore: 0.35,
        factors: ['unwantedSoftware', 'bundleInstall', 'systemModification'],
        impact: 'Unwanted program affecting system behavior.'
      },
      zeroday: {
        baseScore: 0.88,
        factors: ['unknownVulnerability', 'noAvailablePatch', 'activeExploit'],
        impact: 'Unpatched vulnerability being actively exploited.'
      }
    };

    // Risk factors
    this.riskFactors = {
      targetedSystem: {
        critical: 3.0,
        server: 2.8,
        workstation: 2.0
      },
      executionContext: {
        system: 3.0,
        admin: 2.5,
        user: 1.5,
        guest: 1.0
      },
      networkAccess: {
        internet: 2.8,
        intranet: 2.0,
        local: 1.2,
        isolated: 1.0
      },
      dataAccess: {
        credentials: 3.0,
        documents: 2.2,
        system: 1.8,
        none: 1.0
      },
      persistence: {
        registry: 2.5,
        scheduler: 2.3,
        startup: 2.2,
        service: 2.8,
        bootkit: 3.0,
        none: 1.0
      }
    };

    // Response actions by severity
    this.responseActions = {
      critical: [
        'Immediately isolate affected system from network',
        'Preserve forensic evidence (memory dump, logs)',
        'Activate incident response team',
        'Notify security stakeholders',
        'Begin root cause analysis'
      ],
      high: [
        'Isolate system from network within 30 minutes',
        'Quarantine detected files',
        'Scan all connected systems for similar threats',
        'Review security logs for indicators of compromise',
        'Update detection signatures'
      ],
      medium: [
        'Quarantine detected files',
        'Scan system thoroughly',
        'Update definitions and signatures',
        'Monitor system for 48 hours'
      ],
      low: [
        'Monitor system',
        'Update security software',
        'Review system logs'
      ],
      info: [
        'Document finding',
        'Review logs periodically'
      ]
    };

    this.classificationHistory = [];
  }

  classifyThreat(detection) {
    if (!detection) return null;

    let score = this.calculateBaseScore(detection);
    const factors = this.extractRiskFactors(detection);

    // Apply risk factor multipliers
    Object.entries(factors).forEach(([category, value]) => {
      if (this.riskFactors[category] && this.riskFactors[category][value]) {
        score *= this.riskFactors[category][value];
      }
    });

    // Normalize score
    score = Math.min(Math.max(score, 0), 1);

    const severity = this.getSeverityLevel(score);
    const threatType = this.identifyThreatType(detection);

    const classification = {
      timestamp: Date.now(),
      threatId: detection.id || `THREAT_${Date.now()}`,
      threatType,
      score: parseFloat(score.toFixed(3)),
      severity,
      confidence: detection.confidence || 0.85,
      riskFactors: factors,
      recommendedActions: this.getRecommendedActions(severity),
      estimatedImpact: this.estimateImpact(severity),
      responseTimeframe: this.getResponseTimeframe(severity),
      summary: `${severity.toUpperCase()}-severity ${threatType} threat detected`
    };

    // Store history
    this.classificationHistory.push(classification);
    if (this.classificationHistory.length > 500) {
      this.classificationHistory.shift();
    }

    return classification;
  }

  calculateBaseScore(detection) {
    let score = 0.5;
    const threatName = (detection.threatName || '').toLowerCase();
    
    Object.entries(this.threatCharacteristics).forEach(([type, config]) => {
      if (threatName.includes(type)) {
        score = config.baseScore;
      }
    });

    if (detection.confidence) {
      score = score * 0.7 + (detection.confidence * 0.3);
    }

    return score;
  }

  extractRiskFactors(detection) {
    return {
      targetedSystem: this.assessTargetedSystem(detection),
      executionContext: this.assessExecutionContext(detection),
      networkAccess: this.assessNetworkAccess(detection),
      dataAccess: this.assessDataAccess(detection),
      persistence: this.assessPersistence(detection)
    };
  }

  assessTargetedSystem(detection) {
    if (detection.processName) {
      if (detection.processName.includes('winlogon') || detection.processName.includes('lsass')) {
        return 'critical';
      }
      if (detection.processName.includes('explorer') || detection.processName.includes('svchost')) {
        return 'server';
      }
    }
    return 'workstation';
  }

  assessExecutionContext(detection) {
    if (detection.privilegeLevel === 'system') return 'system';
    if (detection.privilegeLevel === 'admin') return 'admin';
    if (detection.privilegeLevel === 'user') return 'user';
    return 'guest';
  }

  assessNetworkAccess(detection) {
    if (detection.networkAccess === 'internet') return 'internet';
    if (detection.networkAccess === 'intranet') return 'intranet';
    if (detection.networkAccess === 'local') return 'local';
    return 'isolated';
  }

  assessDataAccess(detection) {
    if (detection.accessesCredentials) return 'credentials';
    if (detection.accessesDocuments) return 'documents';
    if (detection.accessesSystemFiles) return 'system';
    return 'none';
  }

  assessPersistence(detection) {
    if (detection.persistenceType) return detection.persistenceType;
    return 'none';
  }

  getSeverityLevel(score) {
    if (score >= 0.9) return this.SEVERITY_LEVELS.CRITICAL;
    if (score >= 0.7) return this.SEVERITY_LEVELS.HIGH;
    if (score >= 0.5) return this.SEVERITY_LEVELS.MEDIUM;
    if (score >= 0.3) return this.SEVERITY_LEVELS.LOW;
    return this.SEVERITY_LEVELS.INFO;
  }

  identifyThreatType(detection) {
    const threatName = (detection.threatName || '').toLowerCase();
    const threatType = detection.threatType || 'unknown';

    for (const [type] of Object.entries(this.threatCharacteristics)) {
      if (threatName.includes(type) || threatType.includes(type)) {
        return type;
      }
    }

    return 'unknown';
  }

  getRecommendedActions(severity) {
    return this.responseActions[severity] || this.responseActions.info;
  }

  estimateImpact(severity) {
    const impacts = {
      critical: {
        business: 'Complete system compromise',
        financial: '$100,000+',
        dataRisk: 'Extreme - All data exposed',
        operational: 'Complete service disruption'
      },
      high: {
        business: 'Significant compromise',
        financial: '$10,000-$100,000',
        dataRisk: 'High - Sensitive data at risk',
        operational: 'Service degradation'
      },
      medium: {
        business: 'Partial compromise',
        financial: '$1,000-$10,000',
        dataRisk: 'Medium - Some data at risk',
        operational: 'Minor service impact'
      },
      low: {
        business: 'Minimal impact',
        financial: '$100-$1,000',
        dataRisk: 'Low - Limited data exposure',
        operational: 'Negligible impact'
      },
      info: {
        business: 'No direct impact',
        financial: '$0-$100',
        dataRisk: 'Minimal - No data exposure',
        operational: 'No impact'
      }
    };

    return impacts[severity] || impacts.info;
  }

  getResponseTimeframe(severity) {
    const timeframes = {
      critical: { minutes: 5, description: 'Immediate - Drop everything' },
      high: { minutes: 30, description: 'Within 30 minutes' },
      medium: { minutes: 180, description: 'Within 3 hours' },
      low: { minutes: 1440, description: 'Within 24 hours' },
      info: { minutes: 10080, description: 'Within 1 week' }
    };

    return timeframes[severity] || timeframes.info;
  }

  getStatistics() {
    const stats = {
      total: this.classificationHistory.length,
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      byThreatType: {}
    };

    let totalScore = 0;
    this.classificationHistory.forEach(classification => {
      stats.bySeverity[classification.severity]++;
      stats.byThreatType[classification.threatType] = (stats.byThreatType[classification.threatType] || 0) + 1;
      totalScore += classification.score;
    });

    stats.averageScore = stats.total > 0 ? (totalScore / stats.total).toFixed(3) : 0;

    return stats;
  }
}

// Create singleton instance with error handling
let threatSeverityClassifier;
try {
  threatSeverityClassifier = new ThreatSeverityClassifier();
} catch (error) {
  console.error('Failed to initialize ThreatSeverityClassifier:', error);
  threatSeverityClassifier = {
    classifyThreat: () => ({
      severity: 'unknown',
      score: 0,
      threatType: 'unknown',
      threatId: `THREAT_${Date.now()}`,
      recommendedActions: [],
      estimatedImpact: { business: 'Unknown', financial: 'Unknown', dataRisk: 'Unknown', operational: 'Unknown' },
      responseTimeframe: { minutes: 60, description: 'Investigate immediately' },
      summary: 'Unknown threat detected'
    }),
    getStatistics: () => ({ total: 0, bySeverity: {}, byThreatType: {}, averageScore: 0 })
  };
}

export default threatSeverityClassifier;
