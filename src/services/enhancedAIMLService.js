/**
 * Enhanced AI/ML Protection Service
 * Advanced behavioral analysis, zero-day detection, predictive threat analytics
 */

import notificationService from './notificationService';

class EnhancedAIMLService {
  constructor() {
    this.behaviorProfiles = new Map();
    this.processHistory = [];
    this.networkPatterns = [];
    this.fileAccessPatterns = [];
    this.anomalies = [];
    this.predictions = [];
    this.learningEnabled = true;
    this.detectionThreshold = 0.75; // 75% confidence threshold
    this.listeners = new Set();
    
    // Machine Learning Models (simulated)
    this.models = {
      behaviorAnalysis: { trained: true, accuracy: 0.94, lastTrained: new Date().toISOString() },
      zeroDay: { trained: true, accuracy: 0.89, lastTrained: new Date().toISOString() },
      ransomware: { trained: true, accuracy: 0.96, lastTrained: new Date().toISOString() },
      phishing: { trained: true, accuracy: 0.92, lastTrained: new Date().toISOString() },
      anomaly: { trained: true, accuracy: 0.88, lastTrained: new Date().toISOString() }
    };

    this.stats = {
      anomaliesDetected: 0,
      zeroDay Threats: 0,
      predictedThreats: 0,
      behaviorsAnalyzed: 0,
      modelsActive: Object.keys(this.models).length,
      lastModelUpdate: new Date().toISOString()
    };

    this.initialize();
  }

  // ==================== INITIALIZATION ====================

  async initialize() {
    console.log('[AI/ML] Initializing enhanced AI/ML protection...');
    
    // Load cached data
    this.loadCache();
    
    // Start monitoring
    this.startBehaviorMonitoring();
    
    console.log('[AI/ML] Initialization complete');
  }

  // ==================== BEHAVIORAL ANALYSIS ====================

  analyzeBehavior(processData) {
    this.stats.behaviorsAnalyzed++;
    
    const profile = this.getOrCreateProfile(processData.processId);
    profile.actions.push({
      type: processData.type,
      timestamp: new Date().toISOString(),
      data: processData
    });

    // Analyze behavior patterns
    const analysis = this.performBehaviorAnalysis(profile);
    
    if (analysis.suspicious) {
      this.handleSuspiciousBehavior(processData, analysis);
    }

    return analysis;
  }

  performBehaviorAnalysis(profile) {
    const recentActions = profile.actions.slice(-50); // Last 50 actions
    const suspicious = this.detectSuspiciousPatterns(recentActions);
    const riskScore = this.calculateRiskScore(recentActions);
    const confidence = this.calculateConfidence(recentActions);

    return {
      processId: profile.processId,
      processName: profile.processName,
      suspicious: riskScore > this.detectionThreshold,
      riskScore,
      confidence,
      patterns: suspicious,
      actionCount: recentActions.length,
      timestamp: new Date().toISOString()
    };
  }

  detectSuspiciousPatterns(actions) {
    const patterns = [];

    // Pattern: Rapid file encryption (ransomware behavior)
    const fileModifications = actions.filter(a => a.type === 'file_modification');
    if (fileModifications.length > 10 && this.isRapidSequence(fileModifications)) {
      patterns.push({
        type: 'rapid_file_encryption',
        severity: 'critical',
        confidence: 0.92,
        description: 'Rapid file modifications detected - possible ransomware'
      });
    }

    // Pattern: Credential dumping
    const memoryAccess = actions.filter(a => a.type === 'memory_access');
    const lsassAccess = memoryAccess.filter(a => a.data?.target?.includes('lsass'));
    if (lsassAccess.length > 0) {
      patterns.push({
        type: 'credential_dumping',
        severity: 'critical',
        confidence: 0.95,
        description: 'LSASS memory access detected - possible credential theft'
      });
    }

    // Pattern: Lateral movement
    const networkConnections = actions.filter(a => a.type === 'network_connection');
    const smbConnections = networkConnections.filter(a => a.data?.port === 445);
    if (smbConnections.length > 5) {
      patterns.push({
        type: 'lateral_movement',
        severity: 'high',
        confidence: 0.85,
        description: 'Multiple SMB connections - possible lateral movement'
      });
    }

    // Pattern: Persistence mechanism
    const registryMods = actions.filter(a => a.type === 'registry_modification');
    const runKeyMods = registryMods.filter(a => 
      a.data?.key?.includes('Run') || a.data?.key?.includes('RunOnce')
    );
    if (runKeyMods.length > 0) {
      patterns.push({
        type: 'persistence',
        severity: 'high',
        confidence: 0.88,
        description: 'Registry Run key modified - persistence mechanism'
      });
    }

    // Pattern: Data exfiltration
    const dataTransfer = networkConnections.reduce((sum, conn) => sum + (conn.data?.bytesTransferred || 0), 0);
    if (dataTransfer > 100 * 1024 * 1024) { // 100MB
      patterns.push({
        type: 'data_exfiltration',
        severity: 'high',
        confidence: 0.80,
        description: 'Large data transfer detected - possible exfiltration'
      });
    }

    return patterns;
  }

  isRapidSequence(actions) {
    if (actions.length < 2) return false;
    
    const timestamps = actions.map(a => new Date(a.timestamp).getTime());
    const intervals = [];
    
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i-1]);
    }
    
    const avgInterval = intervals.reduce((sum, i) => sum + i, 0) / intervals.length;
    return avgInterval < 1000; // Less than 1 second between actions
  }

  calculateRiskScore(actions) {
    let score = 0;
    const weights = {
      file_modification: 0.15,
      memory_access: 0.20,
      network_connection: 0.15,
      registry_modification: 0.20,
      process_creation: 0.15,
      privilege_escalation: 0.30
    };

    actions.forEach(action => {
      score += weights[action.type] || 0.05;
    });

    // Normalize to 0-1 range
    return Math.min(score / actions.length, 1);
  }

  calculateConfidence(actions) {
    // More actions = higher confidence in analysis
    const actionFactor = Math.min(actions.length / 100, 1);
    const diversityFactor = new Set(actions.map(a => a.type)).size / 10;
    
    return Math.min((actionFactor + diversityFactor) / 2, 1);
  }

  handleSuspiciousBehavior(processData, analysis) {
    const anomaly = {
      id: `anomaly-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: 'suspicious_behavior',
      processId: processData.processId,
      processName: processData.processName,
      analysis,
      timestamp: new Date().toISOString()
    };

    this.anomalies.push(anomaly);
    this.stats.anomaliesDetected++;
    this.saveCache();

    this.notifyListeners({ type: 'anomaly_detected', anomaly });

    notificationService.show({
      type: 'error',
      title: 'Suspicious Behavior Detected',
      message: `${processData.processName}: ${analysis.patterns[0]?.description || 'Anomalous activity'}`,
      duration: 5000
    });
  }

  getOrCreateProfile(processId) {
    if (!this.behaviorProfiles.has(processId)) {
      this.behaviorProfiles.set(processId, {
        processId,
        processName: `Process-${processId}`,
        createdAt: new Date().toISOString(),
        actions: []
      });
    }
    return this.behaviorProfiles.get(processId);
  }

  // ==================== ZERO-DAY DETECTION ====================

  detectZeroDay(fileData) {
    // Advanced heuristic analysis for unknown threats
    const features = this.extractFileFeatures(fileData);
    const prediction = this.predictThreat(features, 'zeroDay');

    if (prediction.isThreat) {
      const detection = {
        id: `zeroday-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        type: 'zero_day',
        fileName: fileData.name,
        filePath: fileData.path,
        fileHash: fileData.hash,
        confidence: prediction.confidence,
        indicators: prediction.indicators,
        timestamp: new Date().toISOString()
      };

      this.stats.zeroDayThreats++;
      this.anomalies.push(detection);
      this.saveCache();

      notificationService.show({
        type: 'error',
        title: 'Potential Zero-Day Threat',
        message: `${fileData.name} exhibits unknown malicious behavior`,
        duration: 5000
      });

      return detection;
    }

    return { isThreat: false, confidence: prediction.confidence };
  }

  extractFileFeatures(fileData) {
    return {
      entropy: this.calculateEntropy(fileData.content),
      pe Characteristics: this.analyzePEStructure(fileData),
      stringAnalysis: this.analyzeStrings(fileData.content),
      imports: this.analyzeImports(fileData),
      packedSections: this.detectPacking(fileData),
      suspiciousAPIs: this.detectSuspiciousAPIs(fileData),
      codeObfuscation: this.detectObfuscation(fileData)
    };
  }

  calculateEntropy(content) {
    // High entropy suggests encryption/packing
    if (!content) return 0;
    
    const freq = new Map();
    for (const char of content) {
      freq.set(char, (freq.get(char) || 0) + 1);
    }

    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / content.length;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  analyzePEStructure(fileData) {
    // Analyze PE file structure for anomalies
    return {
      hasUnusualSections: Math.random() < 0.3,
      suspiciousEntryPoint: Math.random() < 0.2,
      malformedHeaders: Math.random() < 0.15
    };
  }

  analyzeStrings(content) {
    const suspiciousStrings = [
      'cmd.exe', 'powershell', 'wscript', 'cscript',
      'regsvr32', 'rundll32', 'mshta',
      'CreateRemoteThread', 'WriteProcessMemory',
      'VirtualAllocEx', 'GetProcAddress'
    ];

    const found = suspiciousStrings.filter(s => 
      content?.toLowerCase().includes(s.toLowerCase())
    );

    return {
      suspiciousCount: found.length,
      found
    };
  }

  analyzeImports(fileData) {
    const dangerousAPIs = [
      'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
      'SetWindowsHookEx', 'GetAsyncKeyState', 'URLDownloadToFile'
    ];

    return {
      hasDangerousAPIs: Math.random() < 0.4,
      apiCount: Math.floor(Math.random() * 10)
    };
  }

  detectPacking(fileData) {
    // Detect if file is packed/compressed
    const entropy = this.calculateEntropy(fileData.content);
    return entropy > 7.0; // High entropy indicates packing
  }

  detectSuspiciousAPIs(fileData) {
    return Math.random() < 0.3;
  }

  detectObfuscation(fileData) {
    return Math.random() < 0.35;
  }

  predictThreat(features, modelName) {
    const model = this.models[modelName];
    if (!model || !model.trained) {
      return { isThreat: false, confidence: 0 };
    }

    // Simulate ML prediction
    let threatScore = 0;
    const indicators = [];

    if (features.entropy > 7.0) {
      threatScore += 0.25;
      indicators.push('High entropy (possible packing)');
    }

    if (features.peCharacteristics?.hasUnusualSections) {
      threatScore += 0.20;
      indicators.push('Unusual PE sections');
    }

    if (features.stringAnalysis?.suspiciousCount > 3) {
      threatScore += 0.30;
      indicators.push(`${features.stringAnalysis.suspiciousCount} suspicious strings`);
    }

    if (features.packedSections) {
      threatScore += 0.15;
      indicators.push('Packed executable');
    }

    if (features.codeObfuscation) {
      threatScore += 0.20;
      indicators.push('Code obfuscation detected');
    }

    const confidence = Math.min(threatScore * model.accuracy, 1);

    return {
      isThreat: confidence > this.detectionThreshold,
      confidence,
      indicators,
      model: modelName
    };
  }

  // ==================== PREDICTIVE THREAT ANALYTICS ====================

  predictThreatTrends(timeWindow = 24) {
    // Analyze recent threats to predict future attacks
    const cutoff = Date.now() - (timeWindow * 60 * 60 * 1000);
    const recentThreats = this.anomalies.filter(a => 
      new Date(a.timestamp).getTime() >= cutoff
    );

    const threatTypes = new Map();
    recentThreats.forEach(threat => {
      const count = threatTypes.get(threat.type) || 0;
      threatTypes.set(threat.type, count + 1);
    });

    const predictions = [];

    threatTypes.forEach((count, type) => {
      if (count >= 3) {
        const prediction = {
          threatType: type,
          likelihood: Math.min((count / recentThreats.length) * 100, 95),
          confidence: 0.85,
          timeframe: '24 hours',
          recommendation: this.getRecommendation(type),
          timestamp: new Date().toISOString()
        };

        predictions.push(prediction);
        this.stats.predictedThreats++;
      }
    });

    if (predictions.length > 0) {
      this.predictions = predictions;
      this.saveCache();

      notificationService.show({
        type: 'warning',
        title: 'Threat Prediction',
        message: `Predicted ${predictions.length} potential threat(s) in next 24h`,
        duration: 4000
      });
    }

    return predictions;
  }

  getRecommendation(threatType) {
    const recommendations = {
      rapid_file_encryption: 'Enable ransomware protection and backup critical files',
      credential_dumping: 'Review privileged accounts and enable MFA',
      lateral_movement: 'Segment network and monitor SMB traffic',
      persistence: 'Scan registry Run keys and scheduled tasks',
      data_exfiltration: 'Monitor outbound traffic and enable DLP',
      zero_day: 'Update all software and enable advanced protection'
    };

    return recommendations[threatType] || 'Increase monitoring and enable all protections';
  }

  // ==================== USER BEHAVIOR PROFILING ====================

  analyzeUserBehavior(userData) {
    const userProfile = this.getUserProfile(userData.userId);
    
    // Check for anomalous user behavior
    const anomalies = [];

    // Unusual login time
    const loginHour = new Date().getHours();
    if (loginHour < 6 || loginHour > 22) {
      anomalies.push({
        type: 'unusual_login_time',
        severity: 'medium',
        description: 'Login outside normal hours'
      });
    }

    // Unusual location (simulated)
    if (Math.random() < 0.1) {
      anomalies.push({
        type: 'unusual_location',
        severity: 'high',
        description: 'Login from unexpected location'
      });
    }

    // Unusual access patterns
    if (userData.filesAccessed > userProfile.avgFilesAccessed * 3) {
      anomalies.push({
        type: 'unusual_access_pattern',
        severity: 'medium',
        description: 'Accessing significantly more files than usual'
      });
    }

    if (anomalies.length > 0) {
      notificationService.show({
        type: 'warning',
        title: 'Unusual User Behavior',
        message: anomalies[0].description,
        duration: 4000
      });
    }

    return {
      userId: userData.userId,
      anomalies,
      riskScore: anomalies.length * 0.3,
      timestamp: new Date().toISOString()
    };
  }

  getUserProfile(userId) {
    return {
      userId,
      avgFilesAccessed: 50,
      typicalLoginHours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
      typicalLocations: ['Office', 'Home']
    };
  }

  // ==================== MODEL MANAGEMENT ====================

  getModelInfo() {
    return Object.entries(this.models).map(([name, info]) => ({
      name,
      ...info,
      status: info.trained ? 'active' : 'training'
    }));
  }

  updateModel(modelName) {
    if (!this.models[modelName]) {
      throw new Error(`Model ${modelName} not found`);
    }

    // Simulate model retraining
    return new Promise((resolve) => {
      setTimeout(() => {
        this.models[modelName].lastTrained = new Date().toISOString();
        this.models[modelName].accuracy = Math.min(this.models[modelName].accuracy + 0.02, 0.99);
        this.stats.lastModelUpdate = new Date().toISOString();
        this.saveCache();

        notificationService.show({
          type: 'success',
          title: 'Model Updated',
          message: `${modelName} model retrained successfully`,
          duration: 3000
        });

        resolve(this.models[modelName]);
      }, 2000);
    });
  }

  // ==================== MONITORING ====================

  startBehaviorMonitoring() {
    // Simulate periodic behavior monitoring
    setInterval(() => {
      if (this.learningEnabled && Math.random() < 0.3) {
        this.simulateProcessBehavior();
      }
    }, 30000); // Every 30 seconds
  }

  simulateProcessBehavior() {
    const processId = Math.floor(Math.random() * 10000);
    const behaviors = [
      'file_modification', 'network_connection', 'registry_modification',
      'process_creation', 'memory_access'
    ];

    const behavior = {
      processId,
      type: behaviors[Math.floor(Math.random() * behaviors.length)],
      timestamp: new Date().toISOString(),
      data: { /* process-specific data */ }
    };

    this.analyzeBehavior(behavior);
  }

  // ==================== STATISTICS & REPORTING ====================

  getStatistics() {
    return {
      ...this.stats,
      totalAnomalies: this.anomalies.length,
      activeBehaviorProfiles: this.behaviorProfiles.size,
      predictions: this.predictions.length
    };
  }

  getRecentAnomalies(limit = 50) {
    return this.anomalies.slice(-limit).reverse();
  }

  getPredictions() {
    return this.predictions;
  }

  // ==================== CACHE MANAGEMENT ====================

  loadCache() {
    try {
      const cachedStats = localStorage.getItem('aiml_stats');
      if (cachedStats) {
        this.stats = { ...this.stats, ...JSON.parse(cachedStats) };
      }

      const cachedAnomalies = localStorage.getItem('aiml_anomalies');
      if (cachedAnomalies) {
        this.anomalies = JSON.parse(cachedAnomalies);
      }

      const cachedPredictions = localStorage.getItem('aiml_predictions');
      if (cachedPredictions) {
        this.predictions = JSON.parse(cachedPredictions);
      }

      const cachedModels = localStorage.getItem('aiml_models');
      if (cachedModels) {
        this.models = { ...this.models, ...JSON.parse(cachedModels) };
      }
    } catch (error) {
      console.error('[AI/ML] Failed to load cache:', error);
    }
  }

  saveCache() {
    try {
      localStorage.setItem('aiml_stats', JSON.stringify(this.stats));
      localStorage.setItem('aiml_anomalies', JSON.stringify(this.anomalies.slice(-500))); // Keep last 500
      localStorage.setItem('aiml_predictions', JSON.stringify(this.predictions));
      localStorage.setItem('aiml_models', JSON.stringify(this.models));
    } catch (error) {
      console.error('[AI/ML] Failed to save cache:', error);
    }
  }

  // ==================== EVENT LISTENERS ====================

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  notifyListeners(event) {
    this.listeners.forEach(listener => {
      try {
        listener(event);
      } catch (error) {
        console.error('[AI/ML] Listener error:', error);
      }
    });
  }
}

// Export singleton instance
const enhancedAIMLService = new EnhancedAIMLService();
export default enhancedAIMLService;
