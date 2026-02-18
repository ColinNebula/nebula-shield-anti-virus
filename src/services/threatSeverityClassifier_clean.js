/**
 * Enhanced Threat Severity Classification Service
 * Categorizes and prioritizes threats based on multiple factors
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
        baseScore: 0.88,
        factors: ['commandAndControl', 'backgroundExecution', 'resourceAbuseForDDoS'],
        impact: 'System will be used for attacks. Isolation recommended.'
      },
      trojan: {
        baseScore: 0.85,
        factors: ['dataTheft', 'remoteAccess', 'privilegeEscalation'],
        impact: 'System credentials/data at risk. Full audit needed.'
      },
      spyware: {
        baseScore: 0.75,
        factors: ['privacyViolation', 'dataCollection', 'keylogging'],
        impact: 'Privacy compromise. Monitor accounts for unauthorized access.'
      },
      adware: {
        baseScore: 0.55,
        factors: ['unwantedAdDisplay', 'browserHijack', 'redirects'],
        impact: 'Nuisance rather than security threat. Removal recommended.'
      },
      pup: {
        baseScore: 0.45,
        factors: ['bundledInstall', 'userUnwanted', 'systemSlowdown'],
        impact: 'Unwanted but low risk. User approval recommended before action.'
      },
      zeroday: {
        baseScore: 0.90,
        factors: ['unknownSignature', 'novelBehavior', 'exploitIndicators'],
        impact: 'New vulnerability detected. Requires analysis and patch.'
      }
    };

    // Risk factors with multipliers
    this.riskFactors = {
      targetedSystem: {
        critical: 3.0,
        server: 2.5,
        workstation: 1.8,
        vm: 1.2
      },
      executionContext: {
        system: 2.5,
        admin: 2.2,
        user: 1.5,
        guest: 1.2
      },
      networkAccess: {
        external: 2.8,
        internal: 1.8,
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

    // Attack chain stages
    this.attackChainStages = {
      reconnaissance: { score: 0.3, name: 'Reconnaissance', action: 'Monitor' },
      weaponization: { score: 0.5, name: 'Weaponization', action: 'Isolate' },
      delivery: { score: 0.6, name: 'Delivery', action: 'Block' },
      exploitation: { score: 0.75, name: 'Exploitation', action: 'Contain' },
      installation: { score: 0.8, name: 'Installation', action: 'Quarantine' },
      commandControl: { score: 0.85, name: 'Command & Control', action: 'Disconnect' },
      actionsOnObjectives: { score: 0.95, name: 'Actions on Objectives', action: 'Emergency Response' }
    };

    // Response actions by severity
    this.responseActions = {
      critical: [
        'Immediately isolate affected system from network',
        'Preserve forensic evidence (memory dump, logs)',
        'Activate incident response team',
        'Notify security stakeholders',
        'Begin root cause analysis',
        'Check for lateral movement indicators',
        'Review access logs for past week'
      ],
      high: [
        'Isolate system from network within 30 minutes',
        'Quarantine detected files',
        'Scan all connected systems for similar threats',
        'Review security logs for indicators of compromise',
        'Update detection signatures',
        'Monitor system closely'
      ],
      medium: [
        'Quarantine detected files',
        'Scan system thoroughly',
        'Update definitions and signatures',
        'Monitor system for 48 hours',
        'Review recent system changes'
      ],
      low: [
        'Remove detected items',
        'Standard cleanup procedures',
        'Monitor for reappearance'
      ],
      info: [
        'Log detection event',
        'No immediate action required',
        'Monitor system normally'
      ]
    };

    // History tracking
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
    if (detection.externalNetworkAccess === true) return 'external';
    if (detection.internalNetworkAccess === true) return 'internal';
    return 'isolated';
  }

  assessDataAccess(detection) {
    if (detection.accessPatterns) {
      if (detection.accessPatterns.includes('credential')) return 'credentials';
      if (detection.accessPatterns.includes('document')) return 'documents';
      if (detection.accessPatterns.includes('system')) return 'system';
    }
    return 'none';
  }

  assessPersistence(detection) {
    if (detection.persistenceMechanisms) {
      if (detection.persistenceMechanisms.includes('bootkit')) return 'bootkit';
      if (detection.persistenceMechanisms.includes('service')) return 'service';
      if (detection.persistenceMechanisms.includes('registry')) return 'registry';
      if (detection.persistenceMechanisms.includes('scheduler')) return 'scheduler';
      if (detection.persistenceMechanisms.includes('startup')) return 'startup';
    }
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
    
    if (threatName.includes('ransomware')) return 'ransomware';
    if (threatName.includes('rootkit')) return 'rootkit';
    if (threatName.includes('botnet') || threatName.includes('bot')) return 'botnet';
    if (threatName.includes('trojan')) return 'trojan';
    if (threatName.includes('spy') || threatName.includes('spyware')) return 'spyware';
    if (threatName.includes('adware') || threatName.includes('pup')) return 'adware';
    if (detection.signature === 'zero-day' || detection.isZeroDay) return 'zeroday';
    
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
        business: 'No business impact',
        financial: '$0',
        dataRisk: 'None',
        operational: 'No operational impact'
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
      byThreatType: {},
      averageScore: 0
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
    classifyThreat: () => ({ severity: 'unknown', score: 0, threatType: 'unknown' }),
    getStatistics: () => ({ total: 0, bySeverity: {}, byThreatType: {} })
  };
}

export default threatSeverityClassifier;
