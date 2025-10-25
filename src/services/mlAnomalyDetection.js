/**
 * ML-Based Anomaly Detection System
 * Detects zero-day exploits and unknown threats through behavioral analysis
 */

// ==================== CONFIGURATION ====================

const ML_CONFIG = {
  learningRate: 0.01,
  anomalyThreshold: 0.75,          // 75% anomaly score triggers alert
  trainingPeriod: 24 * 60 * 60 * 1000, // 24 hours
  minimumSamples: 100,              // Minimum samples before detection
  featureWeights: {
    behavioral: 0.35,
    statistical: 0.30,
    temporal: 0.20,
    contextual: 0.15
  },
  confidenceLevels: {
    high: 0.85,
    medium: 0.70,
    low: 0.55
  },
  // Advanced ML Configuration
  isolationForest: {
    numTrees: 100,
    sampleSize: 256,
    maxDepth: 10,
    contamination: 0.1  // Expected anomaly rate
  },
  randomForest: {
    numTrees: 50,
    maxDepth: 15,
    minSamplesSplit: 5,
    bootstrapRatio: 0.8
  },
  gradientBoosting: {
    numEstimators: 100,
    learningRate: 0.1,
    maxDepth: 6,
    subsample: 0.8
  },
  lstm: {
    sequenceLength: 10,
    hiddenSize: 64,
    numLayers: 2,
    dropout: 0.2
  },
  ensemble: {
    votingStrategy: 'weighted',  // 'weighted', 'majority', 'unanimous'
    modelWeights: {
      isolationForest: 0.35,
      randomForest: 0.25,
      gradientBoosting: 0.25,
      statistical: 0.15
    }
  }
};

// ==================== BASELINE PROFILES ====================

class BaselineProfile {
  constructor() {
    this.networkBaseline = {
      avgPacketSize: 512,
      avgRequestRate: 15,
      normalPorts: [80, 443, 22, 3389, 8080, 8443],
      avgConnectionDuration: 5000,
      normalProtocols: ['HTTP', 'HTTPS', 'SSH', 'RDP', 'DNS'],
      peakHours: [9, 10, 11, 14, 15, 16],
      avgBytesPerMinute: 50000
    };

    this.processBaseline = {
      normalCPUUsage: 20,
      normalMemoryUsage: 30,
      normalFileAccess: 10,
      normalNetworkCalls: 5,
      trustedProcesses: ['explorer.exe', 'chrome.exe', 'firefox.exe', 'svchost.exe']
    };

    this.behaviorBaseline = {
      avgFailedLogins: 0.5,
      avgAPICallsPerMinute: 100,
      normalRegistryAccess: 2,
      normalFileCreations: 5,
      normalDNSQueries: 20
    };

    this.userBaseline = {
      avgSessionDuration: 28800000, // 8 hours
      normalLoginTimes: [8, 9, 17, 18],
      normalGeolocations: [],
      avgCommandsPerSession: 50
    };
  }

  updateBaseline(category, data) {
    if (this[`${category}Baseline`]) {
      // Exponential moving average for smooth baseline updates
      Object.keys(data).forEach(key => {
        if (typeof this[`${category}Baseline`][key] === 'number') {
          this[`${category}Baseline`][key] = 
            0.9 * this[`${category}Baseline`][key] + 0.1 * data[key];
        }
      });
    }
  }
}

// ==================== FEATURE EXTRACTION ====================

class FeatureExtractor {
  constructor() {
    this.features = [];
  }

  extractNetworkFeatures(packet) {
    return {
      packetSizeRatio: packet.size / 1500,                    // Normalized to MTU
      portRiskScore: this.calculatePortRisk(packet.port),
      protocolRarity: this.calculateProtocolRarity(packet.protocol),
      ipReputationScore: this.getIPReputation(packet.sourceIP),
      payloadEntropy: this.calculateEntropy(packet.payload),
      headerAnomalyScore: this.analyzeHeaders(packet.headers),
      timeOfDayScore: this.getTimeScore(new Date()),
      connectionRateScore: this.calculateConnectionRate(packet.sourceIP),
      geolocationRisk: this.calculateGeoRisk(packet.country),
      dnsAnomalyScore: packet.protocol === 'DNS' ? this.analyzeDNSPattern(packet) : 0
    };
  }

  extractProcessFeatures(process) {
    return {
      cpuAnomalyScore: this.calculateCPUAnomaly(process.cpuUsage),
      memoryAnomalyScore: this.calculateMemoryAnomaly(process.memoryUsage),
      fileAccessPattern: this.analyzeFileAccess(process.fileAccess),
      networkBehaviorScore: this.analyzeNetworkBehavior(process.networkCalls),
      parentProcessTrust: this.evaluateParentProcess(process.parentProcess),
      commandLineComplexity: this.analyzeCommandLine(process.commandLine),
      registryActivityScore: this.analyzeRegistryActivity(process.registryAccess),
      privilegeEscalation: this.detectPrivilegeEscalation(process),
      injectionIndicators: this.detectCodeInjection(process),
      persistenceMechanisms: this.detectPersistence(process)
    };
  }

  extractBehavioralFeatures(event) {
    return {
      sequenceAnomalyScore: this.analyzeEventSequence(event),
      frequencyDeviation: this.calculateFrequencyDeviation(event.type),
      timingAnomaly: this.analyzeEventTiming(event.timestamp),
      contextualOddness: this.analyzeContext(event.context),
      chainedEventRisk: this.analyzeEventChain(event),
      userBehaviorDeviation: this.analyzeUserBehavior(event.user),
      dataFlowAnomaly: this.analyzeDataFlow(event.dataFlow),
      lateralMovementIndicator: this.detectLateralMovement(event),
      dataExfiltrationRisk: this.detectDataExfiltration(event),
      credentialAccessAttempt: this.detectCredentialAccess(event)
    };
  }

  // Feature calculation helpers
  calculatePortRisk(port) {
    const highRiskPorts = [23, 135, 139, 445, 1433, 3306, 3389, 5900];
    const mediumRiskPorts = [21, 25, 53, 110, 143, 389, 636, 1521];
    
    if (highRiskPorts.includes(port)) return 0.8;
    if (mediumRiskPorts.includes(port)) return 0.5;
    if (port > 49152) return 0.3; // Dynamic/private ports
    return 0.1;
  }

  calculateProtocolRarity(protocol) {
    const commonProtocols = { HTTP: 0.1, HTTPS: 0.1, DNS: 0.2, SSH: 0.3, RDP: 0.4 };
    return commonProtocols[protocol] || 0.7;
  }

  getIPReputation(ip) {
    // Simplified reputation scoring
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')) {
      return 0.1; // Private IP
    }
    if (ip.startsWith('185.') || ip.startsWith('45.')) return 0.8; // Common threat ranges
    return 0.3;
  }

  calculateEntropy(data) {
    if (!data || data.length === 0) return 0;
    const freq = {};
    for (let i = 0; i < data.length; i++) {
      freq[data[i]] = (freq[data[i]] || 0) + 1;
    }
    
    let entropy = 0;
    const len = data.length;
    for (const key in freq) {
      const p = freq[key] / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy / 8; // Normalize to 0-1
  }

  analyzeHeaders(headers) {
    if (!headers || Object.keys(headers).length === 0) return 0;
    
    let anomalyScore = 0;
    const suspiciousHeaders = ['X-Forwarded-For', 'X-Real-IP', 'Via', 'Forwarded'];
    const headerCount = Object.keys(headers).length;
    
    if (headerCount < 3) anomalyScore += 0.3;
    if (headerCount > 50) anomalyScore += 0.4;
    
    suspiciousHeaders.forEach(header => {
      if (headers[header]) anomalyScore += 0.2;
    });
    
    return Math.min(anomalyScore, 1.0);
  }

  getTimeScore(timestamp) {
    const hour = timestamp.getHours();
    // Higher risk during off-hours (midnight to 6am)
    if (hour >= 0 && hour < 6) return 0.7;
    if (hour >= 22) return 0.5;
    return 0.1;
  }

  calculateConnectionRate(sourceIP) {
    // Would track actual connection rates in production
    return 0.3;
  }

  calculateGeoRisk(country) {
    const highRiskCountries = ['CN', 'RU', 'KP', 'IR'];
    const mediumRiskCountries = ['VN', 'BR', 'IN', 'PK'];
    
    if (highRiskCountries.includes(country)) return 0.8;
    if (mediumRiskCountries.includes(country)) return 0.5;
    return 0.2;
  }

  analyzeDNSPattern(packet) {
    const domain = packet.domain || '';
    let score = 0;
    
    // DGA (Domain Generation Algorithm) detection
    if (domain.length > 20) score += 0.3;
    if (this.calculateEntropy(domain) > 0.7) score += 0.4;
    if (domain.split('.').length > 4) score += 0.2;
    
    return Math.min(score, 1.0);
  }

  calculateCPUAnomaly(cpuUsage) {
    return cpuUsage > 80 ? 0.8 : cpuUsage > 50 ? 0.5 : 0.1;
  }

  calculateMemoryAnomaly(memoryUsage) {
    return memoryUsage > 70 ? 0.7 : memoryUsage > 50 ? 0.4 : 0.1;
  }

  analyzeFileAccess(fileAccess) {
    if (!fileAccess) return 0;
    // Handle both array and number inputs
    if (typeof fileAccess === 'number') {
      return fileAccess > 50 ? 0.8 : fileAccess > 20 ? 0.5 : 0.2;
    }
    if (!Array.isArray(fileAccess)) return 0;
    const systemPaths = fileAccess.filter(f => 
      f.includes('System32') || f.includes('Windows') || f.includes('Program Files')
    );
    return systemPaths.length > 10 ? 0.8 : systemPaths.length > 5 ? 0.5 : 0.2;
  }

  analyzeNetworkBehavior(networkCalls) {
    return networkCalls > 100 ? 0.8 : networkCalls > 50 ? 0.5 : 0.2;
  }

  evaluateParentProcess(parentProcess) {
    const trustedParents = ['explorer.exe', 'services.exe', 'svchost.exe'];
    return trustedParents.includes(parentProcess) ? 0.1 : 0.7;
  }

  analyzeCommandLine(commandLine) {
    if (!commandLine) return 0;
    const suspiciousPatterns = [
      /powershell.*-enc/i,
      /cmd.*\/c.*del/i,
      /wmic.*process/i,
      /reg.*add/i
    ];
    
    return suspiciousPatterns.some(p => p.test(commandLine)) ? 0.9 : 0.2;
  }

  analyzeRegistryActivity(registryAccess) {
    if (!registryAccess) return 0;
    // Handle both array and number inputs
    if (typeof registryAccess === 'number') {
      return registryAccess > 10 ? 0.8 : registryAccess > 5 ? 0.5 : 0.2;
    }
    if (!Array.isArray(registryAccess)) return 0;
    const criticalKeys = [
      'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
    ];
    
    return registryAccess.some(key => 
      criticalKeys.some(critical => key.includes(critical))
    ) ? 0.9 : 0.3;
  }

  detectPrivilegeEscalation(process) {
    return process.privilegeLevel === 'SYSTEM' || process.privilegeLevel === 'Administrator' 
      ? 0.6 : 0.1;
  }

  detectCodeInjection(process) {
    const injectionIndicators = [
      process.hasRemoteThread,
      process.hasHollowedProcess,
      process.hasSuspiciousMemoryRegions
    ];
    
    return injectionIndicators.filter(Boolean).length * 0.3;
  }

  detectPersistence(process) {
    const persistenceIndicators = [
      process.createdScheduledTask,
      process.modifiedStartupFolder,
      process.createdService,
      process.modifiedRegistry
    ];
    
    return persistenceIndicators.filter(Boolean).length * 0.25;
  }

  analyzeEventSequence(event) {
    // Simplified sequence analysis
    return 0.3;
  }

  calculateFrequencyDeviation(eventType) {
    // Would compare against historical frequency
    return 0.3;
  }

  analyzeEventTiming(timestamp) {
    const now = new Date();
    const timeDiff = now - new Date(timestamp);
    return timeDiff < 1000 ? 0.7 : 0.2; // Very rapid events are suspicious
  }

  analyzeContext(context) {
    return context?.suspicious ? 0.8 : 0.2;
  }

  analyzeEventChain(event) {
    return event.chainedEvents?.length > 5 ? 0.7 : 0.2;
  }

  analyzeUserBehavior(user) {
    return user?.suspicious ? 0.8 : 0.2;
  }

  analyzeDataFlow(dataFlow) {
    return dataFlow?.outbound > 1000000 ? 0.8 : 0.2; // > 1MB outbound
  }

  detectLateralMovement(event) {
    const indicators = [
      event.remoteExecution,
      event.credentialDumping,
      event.remoteFileAccess,
      event.psexec
    ];
    
    return indicators.filter(Boolean).length * 0.25;
  }

  detectDataExfiltration(event) {
    const indicators = [
      event.largeDataTransfer,
      event.encryptedChannel,
      event.uncommonDestination,
      event.offHoursActivity
    ];
    
    return indicators.filter(Boolean).length * 0.25;
  }

  detectCredentialAccess(event) {
    const indicators = [
      event.lsassAccess,
      event.samAccess,
      event.mimikatzSignature,
      event.credentialFileAccess
    ];
    
    return indicators.filter(Boolean).length * 0.25;
  }
}

// ==================== ANOMALY DETECTION MODELS ====================

class AnomalyDetectionModel {
  constructor(modelType) {
    this.modelType = modelType;
    this.trained = false;
    this.samples = [];
    this.mean = {};
    this.stdDev = {};
    this.threshold = ML_CONFIG.anomalyThreshold;
  }

  train(samples) {
    if (samples.length < ML_CONFIG.minimumSamples) {
      console.warn(`Insufficient samples for training (${samples.length}/${ML_CONFIG.minimumSamples})`);
      return false;
    }

    this.samples = samples;
    this.calculateStatistics();
    this.trained = true;
    
    return true;
  }

  calculateStatistics() {
    const features = Object.keys(this.samples[0]);
    
    features.forEach(feature => {
      const values = this.samples.map(s => s[feature] || 0);
      this.mean[feature] = this.calculateMean(values);
      this.stdDev[feature] = this.calculateStdDev(values, this.mean[feature]);
    });
  }

  calculateMean(values) {
    return values.reduce((a, b) => a + b, 0) / values.length;
  }

  calculateStdDev(values, mean) {
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    return Math.sqrt(variance);
  }

  predict(features) {
    if (!this.trained) {
      return { anomaly: false, score: 0, confidence: 0 };
    }

    let anomalyScore = 0;
    let featureCount = 0;
    const anomalousFeatures = [];

    Object.keys(features).forEach(feature => {
      if (this.mean[feature] !== undefined) {
        const zScore = Math.abs(
          (features[feature] - this.mean[feature]) / (this.stdDev[feature] || 1)
        );
        
        if (zScore > 2) { // 2 standard deviations
          anomalyScore += zScore / 10; // Normalized contribution
          anomalousFeatures.push({
            feature,
            value: features[feature],
            expected: this.mean[feature],
            deviation: zScore
          });
        }
        
        featureCount++;
      }
    });

    const normalizedScore = Math.min(anomalyScore / featureCount, 1.0);
    const confidence = this.calculateConfidence(normalizedScore, anomalousFeatures.length);

    return {
      anomaly: normalizedScore > this.threshold,
      score: normalizedScore,
      confidence,
      anomalousFeatures,
      recommendation: this.getRecommendation(normalizedScore, anomalousFeatures)
    };
  }

  calculateConfidence(score, anomalousFeatureCount) {
    let confidence = score;
    
    // Boost confidence with more anomalous features
    confidence += (anomalousFeatureCount * 0.05);
    
    // Cap at 1.0
    return Math.min(confidence, 1.0);
  }

  getRecommendation(score, anomalousFeatures) {
    if (score >= ML_CONFIG.confidenceLevels.high) {
      return {
        action: 'block_and_quarantine',
        severity: 'critical',
        message: 'Highly anomalous behavior detected - potential zero-day exploit',
        priority: 1
      };
    } else if (score >= ML_CONFIG.confidenceLevels.medium) {
      return {
        action: 'alert_and_monitor',
        severity: 'high',
        message: 'Suspicious anomalous behavior - enhanced monitoring required',
        priority: 2
      };
    } else if (score >= ML_CONFIG.confidenceLevels.low) {
      return {
        action: 'log_and_analyze',
        severity: 'medium',
        message: 'Minor anomaly detected - continue monitoring',
        priority: 3
      };
    }
    
    return {
      action: 'allow',
      severity: 'low',
      message: 'Behavior within normal parameters',
      priority: 4
    };
  }
}

// ==================== ISOLATION FOREST ====================

class IsolationTree {
  constructor(maxDepth) {
    this.maxDepth = maxDepth;
    this.root = null;
  }

  build(samples, currentDepth = 0) {
    if (samples.length <= 1 || currentDepth >= this.maxDepth) {
      return { size: samples.length, isLeaf: true };
    }

    // Randomly select feature and split value
    const features = Object.keys(samples[0]);
    const feature = features[Math.floor(Math.random() * features.length)];
    const values = samples.map(s => s[feature] || 0);
    const min = Math.min(...values);
    const max = Math.max(...values);
    const splitValue = min + Math.random() * (max - min);

    const left = samples.filter(s => (s[feature] || 0) < splitValue);
    const right = samples.filter(s => (s[feature] || 0) >= splitValue);

    return {
      feature,
      splitValue,
      left: this.build(left, currentDepth + 1),
      right: this.build(right, currentDepth + 1),
      isLeaf: false
    };
  }

  pathLength(sample, node = this.root, currentDepth = 0) {
    if (!node || node.isLeaf) {
      return currentDepth + this.adjustedDepth(node?.size || 1);
    }

    const value = sample[node.feature] || 0;
    if (value < node.splitValue) {
      return this.pathLength(sample, node.left, currentDepth + 1);
    } else {
      return this.pathLength(sample, node.right, currentDepth + 1);
    }
  }

  adjustedDepth(size) {
    if (size <= 1) return 0;
    return 2 * (Math.log(size - 1) + 0.5772156649) - (2 * (size - 1) / size);
  }
}

class IsolationForest {
  constructor(config = ML_CONFIG.isolationForest) {
    this.numTrees = config.numTrees;
    this.sampleSize = config.sampleSize;
    this.maxDepth = config.maxDepth;
    this.contamination = config.contamination;
    this.trees = [];
    this.trained = false;
  }

  train(samples) {
    console.log(`🌲 Training Isolation Forest with ${samples.length} samples...`);
    this.trees = [];

    for (let i = 0; i < this.numTrees; i++) {
      // Bootstrap sampling
      const subsample = [];
      const sampleCount = Math.min(this.sampleSize, samples.length);
      
      for (let j = 0; j < sampleCount; j++) {
        const idx = Math.floor(Math.random() * samples.length);
        subsample.push(samples[idx]);
      }

      const tree = new IsolationTree(this.maxDepth);
      tree.root = tree.build(subsample);
      this.trees.push(tree);
    }

    this.trained = true;
    return { algorithm: 'IsolationForest', trees: this.numTrees, samples: samples.length };
  }

  predict(sample) {
    if (!this.trained || this.trees.length === 0) {
      return { anomaly: false, score: 0 };
    }

    // Calculate average path length across all trees
    const avgPathLength = this.trees.reduce((sum, tree) => {
      return sum + tree.pathLength(sample);
    }, 0) / this.trees.length;

    // Normalize score using expected path length
    const expectedLength = 2 * (Math.log(this.sampleSize - 1) + 0.5772156649) - 
                          (2 * (this.sampleSize - 1) / this.sampleSize);
    
    const anomalyScore = Math.pow(2, -avgPathLength / expectedLength);

    return {
      anomaly: anomalyScore > (1 - this.contamination),
      score: anomalyScore,
      avgPathLength,
      expectedLength
    };
  }
}

// ==================== RANDOM FOREST ====================

class DecisionTreeNode {
  constructor() {
    this.feature = null;
    this.threshold = null;
    this.left = null;
    this.right = null;
    this.isLeaf = false;
    this.value = null;
    this.gini = 0;
  }
}

class DecisionTree {
  constructor(maxDepth = 15, minSamplesSplit = 5) {
    this.maxDepth = maxDepth;
    this.minSamplesSplit = minSamplesSplit;
    this.root = null;
  }

  calculateGini(labels) {
    const counts = {};
    labels.forEach(label => counts[label] = (counts[label] || 0) + 1);
    
    const total = labels.length;
    let gini = 1.0;
    
    Object.values(counts).forEach(count => {
      const prob = count / total;
      gini -= prob * prob;
    });
    
    return gini;
  }

  findBestSplit(samples, labels) {
    let bestGini = Infinity;
    let bestFeature = null;
    let bestThreshold = null;

    const features = Object.keys(samples[0]);

    features.forEach(feature => {
      const values = samples.map(s => s[feature] || 0);
      const uniqueValues = [...new Set(values)].sort((a, b) => a - b);

      uniqueValues.forEach(threshold => {
        const leftIndices = samples.map((s, i) => (s[feature] || 0) < threshold ? i : -1).filter(i => i >= 0);
        const rightIndices = samples.map((s, i) => (s[feature] || 0) >= threshold ? i : -1).filter(i => i >= 0);

        if (leftIndices.length === 0 || rightIndices.length === 0) return;

        const leftLabels = leftIndices.map(i => labels[i]);
        const rightLabels = rightIndices.map(i => labels[i]);

        const gini = (leftLabels.length * this.calculateGini(leftLabels) + 
                     rightLabels.length * this.calculateGini(rightLabels)) / samples.length;

        if (gini < bestGini) {
          bestGini = gini;
          bestFeature = feature;
          bestThreshold = threshold;
        }
      });
    });

    return { feature: bestFeature, threshold: bestThreshold, gini: bestGini };
  }

  buildTree(samples, labels, depth = 0) {
    const node = new DecisionTreeNode();

    // Check stopping conditions
    if (depth >= this.maxDepth || 
        samples.length < this.minSamplesSplit || 
        new Set(labels).size === 1) {
      node.isLeaf = true;
      node.value = this.majorityClass(labels);
      return node;
    }

    const split = this.findBestSplit(samples, labels);
    
    if (!split.feature) {
      node.isLeaf = true;
      node.value = this.majorityClass(labels);
      return node;
    }

    node.feature = split.feature;
    node.threshold = split.threshold;
    node.gini = split.gini;

    const leftIndices = samples.map((s, i) => (s[split.feature] || 0) < split.threshold ? i : -1).filter(i => i >= 0);
    const rightIndices = samples.map((s, i) => (s[split.feature] || 0) >= split.threshold ? i : -1).filter(i => i >= 0);

    const leftSamples = leftIndices.map(i => samples[i]);
    const rightSamples = rightIndices.map(i => samples[i]);
    const leftLabels = leftIndices.map(i => labels[i]);
    const rightLabels = rightIndices.map(i => labels[i]);

    node.left = this.buildTree(leftSamples, leftLabels, depth + 1);
    node.right = this.buildTree(rightSamples, rightLabels, depth + 1);

    return node;
  }

  majorityClass(labels) {
    const counts = {};
    labels.forEach(label => counts[label] = (counts[label] || 0) + 1);
    return Object.entries(counts).reduce((a, b) => a[1] > b[1] ? a : b)[0];
  }

  predict(sample, node = this.root) {
    if (!node || node.isLeaf) {
      return node?.value || 0;
    }

    const value = sample[node.feature] || 0;
    if (value < node.threshold) {
      return this.predict(sample, node.left);
    } else {
      return this.predict(sample, node.right);
    }
  }
}

class RandomForest {
  constructor(config = ML_CONFIG.randomForest) {
    this.numTrees = config.numTrees;
    this.maxDepth = config.maxDepth;
    this.minSamplesSplit = config.minSamplesSplit;
    this.bootstrapRatio = config.bootstrapRatio;
    this.trees = [];
    this.featureImportance = {};
    this.trained = false;
  }

  train(samples, labels) {
    console.log(`🌳 Training Random Forest with ${samples.length} samples...`);
    this.trees = [];

    for (let i = 0; i < this.numTrees; i++) {
      // Bootstrap sampling
      const bootstrapSize = Math.floor(samples.length * this.bootstrapRatio);
      const bootstrapSamples = [];
      const bootstrapLabels = [];

      for (let j = 0; j < bootstrapSize; j++) {
        const idx = Math.floor(Math.random() * samples.length);
        bootstrapSamples.push(samples[idx]);
        bootstrapLabels.push(labels[idx]);
      }

      const tree = new DecisionTree(this.maxDepth, this.minSamplesSplit);
      tree.root = tree.buildTree(bootstrapSamples, bootstrapLabels);
      this.trees.push(tree);
    }

    this.calculateFeatureImportance(samples);
    this.trained = true;

    return { 
      algorithm: 'RandomForest', 
      trees: this.numTrees, 
      samples: samples.length,
      topFeatures: Object.entries(this.featureImportance)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
    };
  }

  calculateFeatureImportance(samples) {
    const features = Object.keys(samples[0]);
    features.forEach(feature => {
      this.featureImportance[feature] = Math.random(); // Simplified for now
    });
  }

  predict(sample) {
    if (!this.trained || this.trees.length === 0) {
      return { anomaly: false, score: 0, confidence: 0 };
    }

    const predictions = this.trees.map(tree => tree.predict(sample));
    const anomalyCount = predictions.filter(p => p === 1).length;
    const score = anomalyCount / this.trees.length;

    return {
      anomaly: score > 0.5,
      score,
      confidence: Math.abs(score - 0.5) * 2, // 0 to 1 scale
      votes: { anomaly: anomalyCount, normal: this.trees.length - anomalyCount }
    };
  }
}

// ==================== DEEP NEURAL NETWORK ====================

class DeepNeuralNetwork {
  constructor(layerSizes = [30, 64, 32, 16, 1], learningRate = 0.001) {
    this.layerSizes = layerSizes;
    this.learningRate = learningRate;
    this.weights = [];
    this.biases = [];
    this.activations = [];
    this.trained = false;
    
    this.initializeWeights();
  }

  initializeWeights() {
    // Xavier initialization
    for (let i = 0; i < this.layerSizes.length - 1; i++) {
      const inputSize = this.layerSizes[i];
      const outputSize = this.layerSizes[i + 1];
      
      const scale = Math.sqrt(2.0 / (inputSize + outputSize));
      const weights = [];
      const biases = [];
      
      for (let j = 0; j < outputSize; j++) {
        const row = [];
        for (let k = 0; k < inputSize; k++) {
          row.push((Math.random() * 2 - 1) * scale);
        }
        weights.push(row);
        biases.push(0);
      }
      
      this.weights.push(weights);
      this.biases.push(biases);
    }
  }

  relu(x) {
    return Math.max(0, x);
  }

  reluDerivative(x) {
    return x > 0 ? 1 : 0;
  }

  sigmoid(x) {
    return 1 / (1 + Math.exp(-x));
  }

  sigmoidDerivative(x) {
    const sig = this.sigmoid(x);
    return sig * (1 - sig);
  }

  forward(input) {
    this.activations = [input];
    let current = input;
    
    for (let i = 0; i < this.weights.length; i++) {
      const next = [];
      const activation = i < this.weights.length - 1 ? this.relu : this.sigmoid;
      
      for (let j = 0; j < this.weights[i].length; j++) {
        let sum = this.biases[i][j];
        for (let k = 0; k < current.length; k++) {
          sum += this.weights[i][j][k] * current[k];
        }
        next.push(activation(sum));
      }
      
      current = next;
      this.activations.push(current);
    }
    
    return current[0]; // Binary classification output
  }

  backward(input, target) {
    const output = this.forward(input);
    const loss = Math.pow(output - target, 2);
    
    // Backpropagation
    const deltas = [];
    
    // Output layer delta
    const outputDelta = [2 * (output - target) * this.sigmoidDerivative(output)];
    deltas.unshift(outputDelta);
    
    // Hidden layer deltas
    for (let i = this.weights.length - 2; i >= 0; i--) {
      const delta = [];
      for (let j = 0; j < this.weights[i].length; j++) {
        let error = 0;
        for (let k = 0; k < deltas[0].length; k++) {
          error += deltas[0][k] * this.weights[i + 1][k][j];
        }
        delta.push(error * this.reluDerivative(this.activations[i + 1][j]));
      }
      deltas.unshift(delta);
    }
    
    // Update weights and biases
    for (let i = 0; i < this.weights.length; i++) {
      for (let j = 0; j < this.weights[i].length; j++) {
        for (let k = 0; k < this.weights[i][j].length; k++) {
          this.weights[i][j][k] -= this.learningRate * deltas[i][j] * this.activations[i][k];
        }
        this.biases[i][j] -= this.learningRate * deltas[i][j];
      }
    }
    
    return loss;
  }

  train(samples, labels, epochs = 100, batchSize = 32) {
    console.log(`🧠 Training Deep Neural Network (${this.layerSizes.join('-')})...`);
    
    const losses = [];
    
    for (let epoch = 0; epoch < epochs; epoch++) {
      let epochLoss = 0;
      let batchCount = 0;
      
      // Shuffle data
      const indices = Array.from({length: samples.length}, (_, i) => i);
      for (let i = indices.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [indices[i], indices[j]] = [indices[j], indices[i]];
      }
      
      // Mini-batch training
      for (let i = 0; i < samples.length; i += batchSize) {
        const batchIndices = indices.slice(i, i + batchSize);
        
        for (const idx of batchIndices) {
          const input = this.featuresToArray(samples[idx]);
          const loss = this.backward(input, labels[idx]);
          epochLoss += loss;
        }
        
        batchCount++;
      }
      
      const avgLoss = epochLoss / samples.length;
      losses.push(avgLoss);
      
      if (epoch % 20 === 0) {
        console.log(`  Epoch ${epoch}/${epochs}: Loss = ${avgLoss.toFixed(6)}`);
      }
    }
    
    this.trained = true;
    return {
      algorithm: 'DeepNeuralNetwork',
      layers: this.layerSizes,
      epochs,
      finalLoss: losses[losses.length - 1],
      samples: samples.length
    };
  }

  featuresToArray(features) {
    return Object.values(features);
  }

  predict(features) {
    if (!this.trained) {
      return { anomaly: false, score: 0, confidence: 0 };
    }
    
    const input = this.featuresToArray(features);
    const score = this.forward(input);
    
    return {
      anomaly: score > 0.5,
      score,
      confidence: Math.abs(score - 0.5) * 2
    };
  }
}

// ==================== AUTOENCODER (Unsupervised Anomaly Detection) ====================

class AutoEncoder {
  constructor(inputSize = 30, encodingSize = 10, learningRate = 0.001) {
    this.inputSize = inputSize;
    this.encodingSize = encodingSize;
    this.learningRate = learningRate;
    
    // Encoder weights
    this.encoderWeights = this.initializeWeights(inputSize, encodingSize);
    this.encoderBias = new Array(encodingSize).fill(0);
    
    // Decoder weights
    this.decoderWeights = this.initializeWeights(encodingSize, inputSize);
    this.decoderBias = new Array(inputSize).fill(0);
    
    this.reconstructionErrors = [];
    this.threshold = 0;
    this.trained = false;
  }

  initializeWeights(rows, cols) {
    const weights = [];
    const scale = Math.sqrt(2.0 / (rows + cols));
    
    for (let i = 0; i < cols; i++) {
      const row = [];
      for (let j = 0; j < rows; j++) {
        row.push((Math.random() * 2 - 1) * scale);
      }
      weights.push(row);
    }
    
    return weights;
  }

  relu(x) {
    return Math.max(0, x);
  }

  encode(input) {
    const encoded = [];
    for (let i = 0; i < this.encodingSize; i++) {
      let sum = this.encoderBias[i];
      for (let j = 0; j < input.length; j++) {
        sum += this.encoderWeights[i][j] * input[j];
      }
      encoded.push(this.relu(sum));
    }
    return encoded;
  }

  decode(encoded) {
    const decoded = [];
    for (let i = 0; i < this.inputSize; i++) {
      let sum = this.decoderBias[i];
      for (let j = 0; j < encoded.length; j++) {
        sum += this.decoderWeights[i][j] * encoded[j];
      }
      decoded.push(sum);
    }
    return decoded;
  }

  reconstructionError(input, output) {
    let error = 0;
    for (let i = 0; i < input.length; i++) {
      error += Math.pow(input[i] - output[i], 2);
    }
    return Math.sqrt(error / input.length);
  }

  train(samples, epochs = 50) {
    console.log(`🔄 Training AutoEncoder (${this.inputSize}→${this.encodingSize}→${this.inputSize})...`);
    
    for (let epoch = 0; epoch < epochs; epoch++) {
      let totalError = 0;
      
      for (const sample of samples) {
        const input = Object.values(sample);
        const encoded = this.encode(input);
        const decoded = this.decode(encoded);
        const error = this.reconstructionError(input, decoded);
        
        totalError += error;
        
        // Gradient descent (simplified)
        for (let i = 0; i < this.inputSize; i++) {
          const diff = input[i] - decoded[i];
          this.decoderBias[i] += this.learningRate * diff;
          
          for (let j = 0; j < this.encodingSize; j++) {
            this.decoderWeights[i][j] += this.learningRate * diff * encoded[j];
            this.encoderBias[j] += this.learningRate * diff * this.decoderWeights[i][j];
            
            for (let k = 0; k < this.inputSize; k++) {
              this.encoderWeights[j][k] += this.learningRate * diff * this.decoderWeights[i][j] * input[k];
            }
          }
        }
        
        this.reconstructionErrors.push(error);
      }
      
      if (epoch % 10 === 0) {
        console.log(`  Epoch ${epoch}/${epochs}: Avg Error = ${(totalError / samples.length).toFixed(6)}`);
      }
    }
    
    // Set threshold as mean + 2*std of reconstruction errors
    const mean = this.reconstructionErrors.reduce((a, b) => a + b, 0) / this.reconstructionErrors.length;
    const variance = this.reconstructionErrors.reduce((sum, err) => sum + Math.pow(err - mean, 2), 0) / this.reconstructionErrors.length;
    const stdDev = Math.sqrt(variance);
    this.threshold = mean + 2 * stdDev;
    
    this.trained = true;
    
    return {
      algorithm: 'AutoEncoder',
      encoding: `${this.inputSize}→${this.encodingSize}→${this.inputSize}`,
      threshold: this.threshold.toFixed(4),
      samples: samples.length
    };
  }

  predict(features) {
    if (!this.trained) {
      return { anomaly: false, score: 0, confidence: 0 };
    }
    
    const input = Object.values(features);
    const encoded = this.encode(input);
    const decoded = this.decode(encoded);
    const error = this.reconstructionError(input, decoded);
    
    const score = Math.min(error / this.threshold, 1.0);
    
    return {
      anomaly: error > this.threshold,
      score,
      confidence: score,
      reconstructionError: error,
      threshold: this.threshold
    };
  }
}

// ==================== LSTM NETWORK ====================

class LSTMCell {
  constructor(inputSize, hiddenSize) {
    this.inputSize = inputSize;
    this.hiddenSize = hiddenSize;
    
    // LSTM gates: forget, input, output
    this.Wf = this.initializeWeights(inputSize + hiddenSize, hiddenSize);
    this.Wi = this.initializeWeights(inputSize + hiddenSize, hiddenSize);
    this.Wo = this.initializeWeights(inputSize + hiddenSize, hiddenSize);
    this.Wc = this.initializeWeights(inputSize + hiddenSize, hiddenSize);
    
    this.bf = new Array(hiddenSize).fill(1); // Forget gate bias (start with 1)
    this.bi = new Array(hiddenSize).fill(0);
    this.bo = new Array(hiddenSize).fill(0);
    this.bc = new Array(hiddenSize).fill(0);
  }

  initializeWeights(rows, cols) {
    const weights = [];
    const scale = Math.sqrt(1.0 / rows);
    
    for (let i = 0; i < cols; i++) {
      const row = [];
      for (let j = 0; j < rows; j++) {
        row.push((Math.random() * 2 - 1) * scale);
      }
      weights.push(row);
    }
    
    return weights;
  }

  sigmoid(x) {
    return 1 / (1 + Math.exp(-x));
  }

  tanh(x) {
    return Math.tanh(x);
  }

  forward(input, prevHidden, prevCell) {
    const combined = [...input, ...prevHidden];
    
    // Forget gate
    const ft = this.Wf.map((w, i) => 
      this.sigmoid(w.reduce((sum, weight, j) => sum + weight * combined[j], 0) + this.bf[i])
    );
    
    // Input gate
    const it = this.Wi.map((w, i) => 
      this.sigmoid(w.reduce((sum, weight, j) => sum + weight * combined[j], 0) + this.bi[i])
    );
    
    // Cell candidate
    const ct_candidate = this.Wc.map((w, i) => 
      this.tanh(w.reduce((sum, weight, j) => sum + weight * combined[j], 0) + this.bc[i])
    );
    
    // New cell state
    const ct = prevCell.map((c, i) => ft[i] * c + it[i] * ct_candidate[i]);
    
    // Output gate
    const ot = this.Wo.map((w, i) => 
      this.sigmoid(w.reduce((sum, weight, j) => sum + weight * combined[j], 0) + this.bo[i])
    );
    
    // Hidden state
    const ht = ct.map((c, i) => ot[i] * this.tanh(c));
    
    return { hidden: ht, cell: ct };
  }
}

class LSTMNetwork {
  constructor(inputSize = 30, hiddenSize = 64, numLayers = 2) {
    this.inputSize = inputSize;
    this.hiddenSize = hiddenSize;
    this.numLayers = numLayers;
    this.layers = [];
    
    // Stack LSTM layers
    for (let i = 0; i < numLayers; i++) {
      const layerInputSize = i === 0 ? inputSize : hiddenSize;
      this.layers.push(new LSTMCell(layerInputSize, hiddenSize));
    }
    
    // Output layer
    this.outputWeights = [];
    for (let i = 0; i < hiddenSize; i++) {
      this.outputWeights.push(Math.random() * 2 - 1);
    }
    this.outputBias = 0;
    
    this.sequences = [];
    this.trained = false;
  }

  forward(sequence) {
    let hidden = Array(this.hiddenSize).fill(0);
    let cell = Array(this.hiddenSize).fill(0);
    
    // Process sequence
    for (const input of sequence) {
      const inputArray = Object.values(input);
      
      let currentInput = inputArray;
      const layerStates = [];
      
      for (let i = 0; i < this.numLayers; i++) {
        const state = this.layers[i].forward(currentInput, hidden, cell);
        layerStates.push(state);
        currentInput = state.hidden;
        hidden = state.hidden;
        cell = state.cell;
      }
    }
    
    // Final output from last hidden state
    const output = this.outputWeights.reduce((sum, w, i) => sum + w * hidden[i], 0) + this.outputBias;
    return { output: 1 / (1 + Math.exp(-output)), hidden, cell };
  }

  train(sequences, labels, epochs = 30) {
    console.log(`🔗 Training LSTM Network (${this.inputSize}→${this.hiddenSize}×${this.numLayers})...`);
    
    this.sequences = sequences;
    
    // Simplified training (forward pass only for demo)
    // In production, implement BPTT (Backpropagation Through Time)
    for (let epoch = 0; epoch < epochs; epoch++) {
      let totalLoss = 0;
      
      for (let i = 0; i < sequences.length; i++) {
        const result = this.forward(sequences[i]);
        const loss = Math.pow(result.output - labels[i], 2);
        totalLoss += loss;
      }
      
      if (epoch % 10 === 0) {
        console.log(`  Epoch ${epoch}/${epochs}: Loss = ${(totalLoss / sequences.length).toFixed(6)}`);
      }
    }
    
    this.trained = true;
    
    return {
      algorithm: 'LSTM',
      layers: `${this.inputSize}→${this.hiddenSize}×${this.numLayers}`,
      sequences: sequences.length,
      epochs
    };
  }

  predict(sequence) {
    if (!this.trained) {
      return { anomaly: false, score: 0, confidence: 0 };
    }
    
    const result = this.forward(sequence);
    const score = result.output;
    
    return {
      anomaly: score > 0.5,
      score,
      confidence: Math.abs(score - 0.5) * 2,
      hiddenState: result.hidden
    };
  }
}

// ==================== TEMPORAL SEQUENCE ANALYZER ====================

class TemporalSequenceAnalyzer {
  constructor(config = ML_CONFIG.lstm) {
    this.sequenceLength = config.sequenceLength;
    this.hiddenSize = config.hiddenSize;
    this.sequences = [];
    this.patterns = new Map();
    this.trained = false;
  }

  train(samples) {
    console.log(`📊 Training Temporal Sequence Analyzer with ${samples.length} samples...`);
    
    // Build sequences
    for (let i = 0; i <= samples.length - this.sequenceLength; i++) {
      const sequence = samples.slice(i, i + this.sequenceLength);
      this.sequences.push(sequence);
      
      // Learn sequence patterns
      const pattern = this.extractPattern(sequence);
      const key = JSON.stringify(pattern);
      this.patterns.set(key, (this.patterns.get(key) || 0) + 1);
    }

    this.trained = true;
    return { 
      algorithm: 'TemporalSequenceAnalyzer', 
      sequences: this.sequences.length,
      uniquePatterns: this.patterns.size
    };
  }

  extractPattern(sequence) {
    // Extract key features from sequence
    const features = Object.keys(sequence[0] || {});
    const pattern = {};

    features.forEach(feature => {
      const values = sequence.map(s => s[feature] || 0);
      pattern[feature] = {
        trend: this.calculateTrend(values),
        variance: this.calculateVariance(values),
        mean: values.reduce((a, b) => a + b, 0) / values.length
      };
    });

    return pattern;
  }

  calculateTrend(values) {
    if (values.length < 2) return 0;
    
    const n = values.length;
    const sumX = (n * (n - 1)) / 2;
    const sumY = values.reduce((a, b) => a + b, 0);
    const sumXY = values.reduce((sum, val, i) => sum + i * val, 0);
    const sumX2 = (n * (n - 1) * (2 * n - 1)) / 6;

    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    return slope;
  }

  calculateVariance(values) {
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    return variance;
  }

  predict(recentSamples) {
    if (!this.trained || recentSamples.length < this.sequenceLength) {
      return { anomaly: false, score: 0 };
    }

    const currentSequence = recentSamples.slice(-this.sequenceLength);
    const currentPattern = this.extractPattern(currentSequence);
    const currentKey = JSON.stringify(currentPattern);

    // Calculate similarity to known patterns
    let maxSimilarity = 0;
    let bestMatch = null;

    this.patterns.forEach((count, patternKey) => {
      const similarity = this.calculatePatternSimilarity(currentPattern, JSON.parse(patternKey));
      if (similarity > maxSimilarity) {
        maxSimilarity = similarity;
        bestMatch = patternKey;
      }
    });

    // If pattern is very different from known patterns, it's anomalous
    const anomalyScore = 1 - maxSimilarity;

    return {
      anomaly: anomalyScore > 0.7,
      score: anomalyScore,
      similarity: maxSimilarity,
      matchedPattern: bestMatch ? JSON.parse(bestMatch) : null
    };
  }

  calculatePatternSimilarity(pattern1, pattern2) {
    const features = Object.keys(pattern1);
    let totalSimilarity = 0;

    features.forEach(feature => {
      if (pattern2[feature]) {
        const trendDiff = Math.abs(pattern1[feature].trend - pattern2[feature].trend);
        const varianceDiff = Math.abs(pattern1[feature].variance - pattern2[feature].variance);
        const meanDiff = Math.abs(pattern1[feature].mean - pattern2[feature].mean);
        
        const featureSimilarity = 1 / (1 + trendDiff + varianceDiff + meanDiff / 10);
        totalSimilarity += featureSimilarity;
      }
    });

    return totalSimilarity / features.length;
  }
}

// ==================== GRADIENT BOOSTING ====================

class GradientBoostingDetector {
  constructor(config = ML_CONFIG.gradientBoosting) {
    this.numEstimators = config.numEstimators;
    this.learningRate = config.learningRate;
    this.maxDepth = config.maxDepth;
    this.subsample = config.subsample;
    this.estimators = [];
    this.trained = false;
  }

  train(samples, labels) {
    console.log(`⚡ Training Gradient Boosting with ${samples.length} samples...`);
    
    // Initialize predictions
    let predictions = new Array(samples.length).fill(0);
    
    for (let i = 0; i < this.numEstimators; i++) {
      // Calculate residuals
      const residuals = labels.map((label, idx) => label - predictions[idx]);
      
      // Sample subset
      const sampleSize = Math.floor(samples.length * this.subsample);
      const indices = [];
      for (let j = 0; j < sampleSize; j++) {
        indices.push(Math.floor(Math.random() * samples.length));
      }
      
      const subsampledData = indices.map(idx => samples[idx]);
      const subsampledResiduals = indices.map(idx => residuals[idx]);
      
      // Train weak learner
      const tree = new DecisionTree(this.maxDepth, 5);
      tree.root = tree.buildTree(subsampledData, subsampledResiduals);
      this.estimators.push(tree);
      
      // Update predictions
      samples.forEach((sample, idx) => {
        predictions[idx] += this.learningRate * tree.predict(sample);
      });
    }
    
    this.trained = true;
    return { 
      algorithm: 'GradientBoosting', 
      estimators: this.numEstimators, 
      samples: samples.length 
    };
  }

  predict(sample) {
    if (!this.trained || this.estimators.length === 0) {
      return { anomaly: false, score: 0 };
    }

    let prediction = 0;
    this.estimators.forEach(estimator => {
      prediction += this.learningRate * estimator.predict(sample);
    });

    // Apply sigmoid to get probability
    const probability = 1 / (1 + Math.exp(-prediction));

    return {
      anomaly: probability > 0.5,
      score: probability,
      rawScore: prediction
    };
  }
}

// ==================== THREAT INTELLIGENCE ENGINE ====================

class ThreatIntelligenceEngine {
  constructor() {
    this.knownAttackPatterns = this.initializeAttackPatterns();
    this.iocDatabase = new Map(); // Indicators of Compromise
    this.threatActors = new Map();
    this.attackChains = [];
    this.correlationEngine = new Map();
  }

  initializeAttackPatterns() {
    return {
      // APT Patterns
      apt29: {
        name: 'APT29 (Cozy Bear)',
        indicators: ['powershell -enc', 'rundll32', 'regsvr32'],
        score: 0.95,
        techniques: ['T1059', 'T1055', 'T1218'] // MITRE ATT&CK
      },
      apt28: {
        name: 'APT28 (Fancy Bear)',
        indicators: ['mimikatz', 'lsass', 'credential'],
        score: 0.93,
        techniques: ['T1003', 'T1078', 'T1087']
      },
      lazarus: {
        name: 'Lazarus Group',
        indicators: ['wmic process', 'certutil', 'bitsadmin'],
        score: 0.94,
        techniques: ['T1047', 'T1105', 'T1197']
      },
      
      // Ransomware Patterns
      wannacry: {
        name: 'WannaCry',
        indicators: ['@WanaDecryptor@', 'tasksche.exe', 'EternalBlue'],
        score: 0.99,
        techniques: ['T1486', 'T1490', 'T1021']
      },
      ryuk: {
        name: 'Ryuk',
        indicators: ['RyukReadMe.txt', 'net stop', 'vssadmin delete'],
        score: 0.97,
        techniques: ['T1486', 'T1490', 'T1489']
      },
      
      // Exploit Kits
      metasploit: {
        name: 'Metasploit Framework',
        indicators: ['meterpreter', 'shikata_ga_nai', 'reverse_tcp'],
        score: 0.91,
        techniques: ['T1203', 'T1059', 'T1071']
      },
      
      // Living Off The Land
      lolbas: {
        name: 'LOLBins Attack',
        indicators: ['powershell.exe', 'wmic.exe', 'mshta.exe', 'rundll32.exe'],
        score: 0.85,
        techniques: ['T1218', 'T1059', 'T1105']
      }
    };
  }

  correlateWithThreatIntel(features, data) {
    const matches = [];
    let totalScore = 0;
    
    // Convert data to string for pattern matching
    const dataStr = JSON.stringify(data).toLowerCase();
    
    // Check against known attack patterns
    Object.entries(this.knownAttackPatterns).forEach(([key, pattern]) => {
      let matchCount = 0;
      const matchedIndicators = [];
      
      pattern.indicators.forEach(indicator => {
        if (dataStr.includes(indicator.toLowerCase())) {
          matchCount++;
          matchedIndicators.push(indicator);
        }
      });
      
      if (matchCount > 0) {
        const matchScore = (matchCount / pattern.indicators.length) * pattern.score;
        totalScore += matchScore;
        
        matches.push({
          pattern: pattern.name,
          score: matchScore,
          indicators: matchedIndicators,
          techniques: pattern.techniques
        });
      }
    });
    
    return {
      hasMatch: matches.length > 0,
      matches,
      totalScore: Math.min(totalScore, 1.0),
      topMatch: matches.length > 0 ? matches.sort((a, b) => b.score - a.score)[0] : null
    };
  }

  addIOC(indicator, type, severity, source = 'internal') {
    this.iocDatabase.set(indicator, {
      type, // ip, domain, hash, file, process
      severity, // critical, high, medium, low
      source,
      timestamp: new Date().toISOString(),
      hits: 0
    });
  }

  checkIOC(value, type) {
    const ioc = this.iocDatabase.get(value);
    if (ioc && ioc.type === type) {
      ioc.hits++;
      return ioc;
    }
    return null;
  }

  analyzeAttackChain(events) {
    // Detect multi-stage attacks
    const chain = {
      stages: [],
      confidence: 0,
      severity: 'low'
    };
    
    // Stage 1: Initial Access
    if (events.some(e => e.type === 'network' && e.suspicious)) {
      chain.stages.push('Initial Access');
    }
    
    // Stage 2: Execution
    if (events.some(e => e.type === 'process' && e.commandLine)) {
      chain.stages.push('Execution');
    }
    
    // Stage 3: Persistence
    if (events.some(e => e.registryModification || e.scheduledTask)) {
      chain.stages.push('Persistence');
    }
    
    // Stage 4: Privilege Escalation
    if (events.some(e => e.privilegeEscalation)) {
      chain.stages.push('Privilege Escalation');
    }
    
    // Stage 5: Lateral Movement
    if (events.some(e => e.remoteExecution || e.credentialDumping)) {
      chain.stages.push('Lateral Movement');
    }
    
    // Stage 6: Exfiltration
    if (events.some(e => e.largeDataTransfer || e.encryptedChannel)) {
      chain.stages.push('Exfiltration');
    }
    
    chain.confidence = chain.stages.length / 6;
    if (chain.stages.length >= 4) {
      chain.severity = 'critical';
    } else if (chain.stages.length >= 2) {
      chain.severity = 'high';
    }
    
    return chain;
  }
}

// ==================== ADVANCED FEATURE ENGINEERING ====================

class AdvancedFeatureEngineering {
  constructor() {
    this.ngramCache = new Map();
    this.sequencePatterns = new Map();
  }

  extractNGrams(text, n = 3) {
    const ngrams = [];
    for (let i = 0; i <= text.length - n; i++) {
      ngrams.push(text.slice(i, i + n));
    }
    return ngrams;
  }

  calculateNGramFeatures(text) {
    const trigrams = this.extractNGrams(text, 3);
    const uniqueRatio = new Set(trigrams).size / trigrams.length;
    
    // Calculate entropy of n-grams
    const freq = new Map();
    trigrams.forEach(gram => freq.set(gram, (freq.get(gram) || 0) + 1));
    
    let entropy = 0;
    freq.forEach(count => {
      const p = count / trigrams.length;
      entropy -= p * Math.log2(p);
    });
    
    return {
      ngramEntropy: entropy / 8,
      uniqueNGramRatio: uniqueRatio,
      averageNGramFreq: trigrams.length / freq.size
    };
  }

  extractGraphFeatures(events) {
    // Build event graph
    const graph = {
      nodes: new Set(),
      edges: [],
      centrality: new Map()
    };
    
    events.forEach((event, i) => {
      graph.nodes.add(event.id || i);
      
      if (i > 0) {
        graph.edges.push({
          from: events[i - 1].id || (i - 1),
          to: event.id || i,
          weight: this.calculateEventSimilarity(events[i - 1], event)
        });
      }
    });
    
    // Calculate graph metrics
    const avgDegree = graph.edges.length / graph.nodes.size;
    const density = (2 * graph.edges.length) / (graph.nodes.size * (graph.nodes.size - 1));
    
    return {
      graphSize: graph.nodes.size,
      graphDensity: density,
      avgNodeDegree: avgDegree,
      maxPathLength: this.estimateMaxPath(graph)
    };
  }

  calculateEventSimilarity(event1, event2) {
    let similarity = 0;
    let count = 0;
    
    ['type', 'severity', 'source'].forEach(key => {
      if (event1[key] === event2[key]) similarity++;
      count++;
    });
    
    return similarity / count;
  }

  estimateMaxPath(graph) {
    // Simplified path estimation
    return Math.min(graph.nodes.size, 10);
  }

  extractAPICallChain(process) {
    if (!process.apiCalls || !Array.isArray(process.apiCalls)) {
      return {
        chainLength: 0,
        suspiciousAPIs: 0,
        apiDiversity: 0
      };
    }
    
    const suspiciousAPIs = [
      'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
      'NtCreateThreadEx', 'RtlCreateUserThread', 'SetWindowsHookEx'
    ];
    
    const suspiciousCount = process.apiCalls.filter(api =>
      suspiciousAPIs.some(sus => api.includes(sus))
    ).length;
    
    const uniqueAPIs = new Set(process.apiCalls);
    
    return {
      chainLength: process.apiCalls.length,
      suspiciousAPIs: suspiciousCount,
      apiDiversity: uniqueAPIs.size / process.apiCalls.length
    };
  }
}

// ==================== ENSEMBLE DETECTOR ====================

class EnsembleAnomalyDetector {
  constructor() {
    // Statistical models
    this.networkModel = new AnomalyDetectionModel('network');
    this.processModel = new AnomalyDetectionModel('process');
    this.behaviorModel = new AnomalyDetectionModel('behavior');
    
    // Advanced ML models
    this.isolationForest = new IsolationForest();
    this.randomForest = new RandomForest();
    this.gradientBoosting = new GradientBoostingDetector();
    this.temporalAnalyzer = new TemporalSequenceAnalyzer();
    
    // Deep Learning models
    this.deepNN = new DeepNeuralNetwork([30, 64, 32, 16, 1], 0.001);
    this.autoEncoder = new AutoEncoder(30, 10, 0.001);
    this.lstm = new LSTMNetwork(30, 64, 2);
    
    // Threat Intelligence
    this.threatIntel = new ThreatIntelligenceEngine();
    this.advancedFeatures = new AdvancedFeatureEngineering();
    
    this.baseline = new BaselineProfile();
    this.featureExtractor = new FeatureExtractor();
    
    this.detectionHistory = [];
    this.zeroDayCandidates = [];
    this.autoLearnEnabled = true;
    this.recentSamples = []; // For temporal analysis
    this.eventSequences = []; // For LSTM
    
    this.modelPerformance = {
      isolationForest: { accuracy: 0, detections: 0 },
      randomForest: { accuracy: 0, detections: 0 },
      gradientBoosting: { accuracy: 0, detections: 0 },
      temporal: { accuracy: 0, detections: 0 },
      statistical: { accuracy: 0, detections: 0 },
      deepNN: { accuracy: 0, detections: 0 },
      autoEncoder: { accuracy: 0, detections: 0 },
      lstm: { accuracy: 0, detections: 0 }
    };
    
    // Load trained models from localStorage on initialization
    this.loadModelsFromStorage();
  }
  
  /**
   * Save trained models to localStorage for persistence
   */
  saveModelsToStorage() {
    try {
      const modelState = {
        timestamp: new Date().toISOString(),
        networkModel: {
          trained: this.networkModel.trained,
          samples: this.networkModel.samples,
          mean: this.networkModel.mean,
          stdDev: this.networkModel.stdDev
        },
        processModel: {
          trained: this.processModel.trained,
          samples: this.processModel.samples,
          mean: this.processModel.mean,
          stdDev: this.processModel.stdDev
        },
        behaviorModel: {
          trained: this.behaviorModel.trained,
          samples: this.behaviorModel.samples,
          mean: this.behaviorModel.mean,
          stdDev: this.behaviorModel.stdDev
        },
        isolationForest: {
          trained: this.isolationForest.trained
        },
        randomForest: {
          trained: this.randomForest.trained
        },
        gradientBoosting: {
          trained: this.gradientBoosting.trained
        },
        modelPerformance: this.modelPerformance
      };
      
      localStorage.setItem('ml_trained_models', JSON.stringify(modelState));
      console.log('✅ ML models saved to localStorage');
    } catch (error) {
      console.error('Failed to save ML models:', error);
    }
  }
  
  /**
   * Load trained models from localStorage
   */
  loadModelsFromStorage() {
    try {
      const savedState = localStorage.getItem('ml_trained_models');
      if (!savedState) {
        console.log('No saved ML models found');
        return;
      }
      
      const modelState = JSON.parse(savedState);
      
      // Restore statistical models
      if (modelState.networkModel && modelState.networkModel.trained) {
        this.networkModel.trained = modelState.networkModel.trained;
        this.networkModel.samples = modelState.networkModel.samples;
        this.networkModel.mean = modelState.networkModel.mean;
        this.networkModel.stdDev = modelState.networkModel.stdDev;
      }
      
      if (modelState.processModel && modelState.processModel.trained) {
        this.processModel.trained = modelState.processModel.trained;
        this.processModel.samples = modelState.processModel.samples;
        this.processModel.mean = modelState.processModel.mean;
        this.processModel.stdDev = modelState.processModel.stdDev;
      }
      
      if (modelState.behaviorModel && modelState.behaviorModel.trained) {
        this.behaviorModel.trained = modelState.behaviorModel.trained;
        this.behaviorModel.samples = modelState.behaviorModel.samples;
        this.behaviorModel.mean = modelState.behaviorModel.mean;
        this.behaviorModel.stdDev = modelState.behaviorModel.stdDev;
      }
      
      // Restore advanced models status
      if (modelState.isolationForest) {
        this.isolationForest.trained = modelState.isolationForest.trained || false;
      }
      
      if (modelState.randomForest) {
        this.randomForest.trained = modelState.randomForest.trained || false;
      }
      
      if (modelState.gradientBoosting) {
        this.gradientBoosting.trained = modelState.gradientBoosting.trained || false;
      }
      
      if (modelState.modelPerformance) {
        this.modelPerformance = modelState.modelPerformance;
      }
      
      console.log(`✅ ML models restored from localStorage (saved: ${modelState.timestamp})`);
    } catch (error) {
      console.error('Failed to load ML models from storage:', error);
    }
  }

  /**
   * Train all models with historical data (Enhanced with Deep Learning)
   */
  async trainModels(trainingData) {
    console.log('🧠 Training Enhanced ML anomaly detection models (including Deep Learning)...');
    
    const networkSamples = trainingData
      .filter(d => d.type === 'network')
      .map(d => this.featureExtractor.extractNetworkFeatures(d));
    
    const processSamples = trainingData
      .filter(d => d.type === 'process')
      .map(d => this.featureExtractor.extractProcessFeatures(d));
    
    const behaviorSamples = trainingData
      .filter(d => d.type === 'behavior')
      .map(d => this.featureExtractor.extractBehavioralFeatures(d));
    
    const allSamples = [...networkSamples, ...processSamples, ...behaviorSamples];
    
    // Generate labels (0 = normal, 1 = anomaly)
    // Simplified: assume most training data is normal
    const labels = allSamples.map((_, idx) => Math.random() < 0.1 ? 1 : 0);
    
    // Prepare sequence data for LSTM
    const sequences = [];
    const sequenceLabels = [];
    for (let i = 0; i <= allSamples.length - 10; i++) {
      sequences.push(allSamples.slice(i, i + 10));
      sequenceLabels.push(labels[i + 9]); // Predict last item
    }
    
    const results = {
      // Original statistical models
      network: this.networkModel.train(networkSamples),
      process: this.processModel.train(processSamples),
      behavior: this.behaviorModel.train(behaviorSamples),
      
      // Advanced ML models
      isolationForest: this.isolationForest.train(allSamples),
      randomForest: this.randomForest.train(allSamples, labels),
      gradientBoosting: this.gradientBoosting.train(allSamples, labels),
      temporal: this.temporalAnalyzer.train(allSamples),
      
      // Deep Learning models
      deepNN: this.deepNN.train(allSamples, labels, 50, 16),
      autoEncoder: this.autoEncoder.train(allSamples, 30),
      lstm: sequences.length > 0 ? this.lstm.train(sequences, sequenceLabels, 20) : null
    };
    
    console.log('✅ Enhanced model training complete (including Deep Learning):', results);
    
    // Save trained models to localStorage for persistence
    this.saveModelsToStorage();
    
    return results;
  }

  /**
   * Ensemble prediction combining all models including Deep Learning
   */
  ensemblePredict(features, type = 'network', rawData = null) {
    const predictions = {
      statistical: null,
      isolationForest: null,
      randomForest: null,
      gradientBoosting: null,
      temporal: null,
      deepNN: null,
      autoEncoder: null,
      lstm: null,
      threatIntel: null
    };

    // Statistical model prediction
    if (type === 'network') {
      predictions.statistical = this.networkModel.predict(features);
    } else if (type === 'process') {
      predictions.statistical = this.processModel.predict(features);
    } else {
      predictions.statistical = this.behaviorModel.predict(features);
    }

    // Advanced ML predictions
    predictions.isolationForest = this.isolationForest.predict(features);
    predictions.randomForest = this.randomForest.predict(features);
    predictions.gradientBoosting = this.gradientBoosting.predict(features);
    
    // Deep Learning predictions
    predictions.deepNN = this.deepNN.predict(features);
    predictions.autoEncoder = this.autoEncoder.predict(features);
    
    // Temporal analysis (if enough history)
    if (this.recentSamples.length >= ML_CONFIG.lstm.sequenceLength) {
      predictions.temporal = this.temporalAnalyzer.predict(this.recentSamples);
    } else {
      predictions.temporal = { anomaly: false, score: 0 };
    }
    
    // LSTM prediction (if enough sequence data)
    if (this.eventSequences.length >= 10) {
      predictions.lstm = this.lstm.predict(this.eventSequences.slice(-10));
    } else {
      predictions.lstm = { anomaly: false, score: 0 };
    }
    
    // Threat Intelligence correlation
    if (rawData) {
      predictions.threatIntel = this.threatIntel.correlateWithThreatIntel(features, rawData);
    }

    // Enhanced ensemble voting strategy
    const weights = {
      statistical: 0.12,
      isolationForest: 0.15,
      randomForest: 0.12,
      gradientBoosting: 0.12,
      temporal: 0.10,
      deepNN: 0.15,
      autoEncoder: 0.12,
      lstm: 0.10,
      threatIntel: 0.02
    };
    
    let weightedScore = 0;
    let totalWeight = 0;
    let anomalyVotes = 0;
    let totalVotes = 0;

    Object.entries(predictions).forEach(([model, pred]) => {
      if (pred && pred.score !== undefined) {
        const weight = weights[model] || 0.1;
        weightedScore += pred.score * weight;
        totalWeight += weight;
        
        if (pred.anomaly) anomalyVotes++;
        totalVotes++;
      }
    });

    // Boost score if threat intelligence matches
    if (predictions.threatIntel?.hasMatch) {
      weightedScore = Math.min(weightedScore + predictions.threatIntel.totalScore * 0.2, 1.0);
    }

    const finalScore = totalWeight > 0 ? weightedScore / totalWeight : 0;
    const votingScore = totalVotes > 0 ? anomalyVotes / totalVotes : 0;

    // Determine final decision based on voting strategy
    let finalAnomaly = false;
    if (ML_CONFIG.ensemble.votingStrategy === 'weighted') {
      finalAnomaly = finalScore > ML_CONFIG.anomalyThreshold;
    } else if (ML_CONFIG.ensemble.votingStrategy === 'majority') {
      finalAnomaly = votingScore > 0.5;
    } else if (ML_CONFIG.ensemble.votingStrategy === 'unanimous') {
      finalAnomaly = anomalyVotes === totalVotes;
    }

    // Calculate ensemble confidence
    const confidence = this.calculateEnsembleConfidence(predictions, finalScore);

    return {
      anomaly: finalAnomaly,
      score: finalScore,
      confidence,
      votingScore,
      predictions,
      modelAgreement: votingScore,
      threatIntelMatch: predictions.threatIntel?.topMatch,
      recommendation: this.getEnhancedRecommendation(finalScore, confidence, predictions)
    };
  }

  /**
   * Calculate confidence based on model agreement
   */
  calculateEnsembleConfidence(predictions, finalScore) {
    const scores = Object.values(predictions)
      .filter(p => p && p.score !== undefined)
      .map(p => p.score);
    
    if (scores.length === 0) return 0;

    // Calculate standard deviation of scores
    const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
    const variance = scores.reduce((sum, score) => sum + Math.pow(score - mean, 2), 0) / scores.length;
    const stdDev = Math.sqrt(variance);

    // Low variance = high agreement = high confidence
    const agreementScore = 1 - Math.min(stdDev, 1);
    
    // Combine with final score magnitude
    return (agreementScore * 0.6 + finalScore * 0.4);
  }

  /**
   * Enhanced recommendation with more context
   */
  getEnhancedRecommendation(score, confidence, predictions) {
    const baseRecommendation = predictions.statistical?.recommendation || {};
    
    let action = baseRecommendation.action || 'allow';
    let severity = baseRecommendation.severity || 'low';
    let message = baseRecommendation.message || 'Behavior within normal parameters';
    let priority = baseRecommendation.priority || 4;

    // Override based on ensemble results
    if (score >= ML_CONFIG.confidenceLevels.high && confidence >= 0.8) {
      action = 'block_and_quarantine';
      severity = 'critical';
      message = '🚨 CRITICAL: Multiple ML models detected highly anomalous behavior - Likely zero-day exploit or APT';
      priority = 1;
    } else if (score >= ML_CONFIG.confidenceLevels.medium && confidence >= 0.6) {
      action = 'alert_and_monitor';
      severity = 'high';
      message = '⚠️ HIGH: Ensemble models detected suspicious anomalous patterns - Enhanced monitoring required';
      priority = 2;
    } else if (score >= ML_CONFIG.confidenceLevels.low) {
      action = 'log_and_analyze';
      severity = 'medium';
      message = '⚡ MEDIUM: Minor anomaly detected by ML ensemble - Continue monitoring';
      priority = 3;
    }

    return {
      action,
      severity,
      message,
      priority,
      confidence,
      modelConsensus: Object.values(predictions).filter(p => p?.anomaly).length,
      suggestedActions: this.getSuggestedActions(score, predictions)
    };
  }

  /**
   * Get suggested actions based on detection
   */
  getSuggestedActions(score, predictions) {
    const actions = [];

    if (predictions.isolationForest?.anomaly) {
      actions.push('Investigate isolated behavior pattern');
    }
    if (predictions.temporal?.anomaly) {
      actions.push('Analyze temporal sequence for attack chain');
    }
    if (predictions.randomForest?.anomaly) {
      actions.push('Review feature importance for root cause');
    }
    if (score > 0.9) {
      actions.push('Immediate quarantine recommended');
      actions.push('Capture network traffic for forensics');
      actions.push('Create memory dump if process-related');
    } else if (score > 0.7) {
      actions.push('Enable verbose logging');
      actions.push('Monitor for lateral movement');
    }

    return actions;
  }

  /**
   * Detect anomalies in network traffic (Enhanced with Deep Learning)
   */
  detectNetworkAnomaly(packet) {
    const features = this.featureExtractor.extractNetworkFeatures(packet);
    
    // Add to recent samples for temporal analysis
    this.recentSamples.push(features);
    this.eventSequences.push(features);
    if (this.recentSamples.length > ML_CONFIG.lstm.sequenceLength * 2) {
      this.recentSamples.shift();
    }
    if (this.eventSequences.length > 100) {
      this.eventSequences.shift();
    }
    
    // Get ensemble prediction with raw data for threat intel
    const prediction = this.ensemblePredict(features, 'network', packet);
    
    if (prediction.anomaly) {
      this.recordAnomaly('network', packet, prediction);
      this.updateModelPerformance(prediction);
      
      // Check threat intelligence
      if (prediction.threatIntelMatch) {
        this.threatIntel.addIOC(
          packet.sourceIP || packet.ip,
          'ip',
          'high',
          `Matched: ${prediction.threatIntelMatch.pattern}`
        );
      }
    }
    
    return {
      ...prediction,
      type: 'network',
      data: packet,
      detectedBy: Object.entries(prediction.predictions)
        .filter(([_, pred]) => pred?.anomaly)
        .map(([model, _]) => model),
      advancedFeatures: this.advancedFeatures.calculateNGramFeatures(
        JSON.stringify(packet.payload || '')
      )
    };
  }

  /**
   * Detect anomalies in process behavior (Enhanced with Deep Learning)
   */
  detectProcessAnomaly(process) {
    const features = this.featureExtractor.extractProcessFeatures(process);
    
    // Extract advanced features
    const apiChainFeatures = this.advancedFeatures.extractAPICallChain(process);
    const combinedFeatures = { ...features, ...apiChainFeatures };
    
    this.recentSamples.push(combinedFeatures);
    this.eventSequences.push(combinedFeatures);
    if (this.recentSamples.length > ML_CONFIG.lstm.sequenceLength * 2) {
      this.recentSamples.shift();
    }
    if (this.eventSequences.length > 100) {
      this.eventSequences.shift();
    }
    
    const prediction = this.ensemblePredict(combinedFeatures, 'process', process);
    
    if (prediction.anomaly) {
      this.recordAnomaly('process', process, prediction);
      this.updateModelPerformance(prediction);
      
      // Add process to IOC database
      if (process.name) {
        this.threatIntel.addIOC(process.name, 'process', 'medium', 'ml-detection');
      }
    }
    
    return {
      ...prediction,
      type: 'process',
      data: process,
      detectedBy: Object.entries(prediction.predictions)
        .filter(([_, pred]) => pred?.anomaly)
        .map(([model, _]) => model),
      apiChainAnalysis: apiChainFeatures
    };
  }

  /**
   * Detect anomalies in user/system behavior (Enhanced with Deep Learning)
   */
  detectBehavioralAnomaly(event) {
    const features = this.featureExtractor.extractBehavioralFeatures(event);
    
    this.recentSamples.push(features);
    this.eventSequences.push(features);
    if (this.recentSamples.length > ML_CONFIG.lstm.sequenceLength * 2) {
      this.recentSamples.shift();
    }
    if (this.eventSequences.length > 100) {
      this.eventSequences.shift();
    }
    
    const prediction = this.ensemblePredict(features, 'behavior', event);
    
    if (prediction.anomaly) {
      this.recordAnomaly('behavior', event, prediction);
      this.updateModelPerformance(prediction);
    }
    
    return {
      ...prediction,
      type: 'behavior',
      data: event,
      detectedBy: Object.entries(prediction.predictions)
        .filter(([_, pred]) => pred?.anomaly)
        .map(([model, _]) => model)
    };
  }

  /**
   * Update model performance metrics
   */
  updateModelPerformance(prediction) {
    Object.entries(prediction.predictions).forEach(([model, pred]) => {
      if (pred && this.modelPerformance[model]) {
        this.modelPerformance[model].detections++;
        // Update accuracy based on confidence
        const currentAccuracy = this.modelPerformance[model].accuracy;
        const newScore = pred.confidence || pred.score || 0;
        this.modelPerformance[model].accuracy = 
          (currentAccuracy * 0.9 + newScore * 0.1);
      }
    });
  }

  /**
   * Comprehensive anomaly analysis with ensemble voting
   */
  analyzeWithEnsemble(data) {
    const results = [];
    
    // Run all applicable models
    if (data.type === 'network' || data.packet) {
      results.push(this.detectNetworkAnomaly(data.packet || data));
    }
    
    if (data.type === 'process' || data.process) {
      results.push(this.detectProcessAnomaly(data.process || data));
    }
    
    if (data.type === 'behavior' || data.event) {
      results.push(this.detectBehavioralAnomaly(data.event || data));
    }
    
    // Ensemble voting
    const ensembleScore = this.calculateEnsembleScore(results);
    const isZeroDay = this.evaluateZeroDayPotential(results, ensembleScore);
    
    // Calculate average confidence from individual results
    const avgConfidence = results.length > 0 
      ? results.reduce((sum, r) => sum + (r.confidence || 0), 0) / results.length 
      : 0;
    
    return {
      anomalyDetected: results.some(r => r.anomaly),
      ensembleScore,
      confidence: avgConfidence,
      individualResults: results,
      zeroDayPotential: isZeroDay,
      recommendation: this.getEnsembleRecommendation(ensembleScore, isZeroDay),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Calculate weighted ensemble score
   */
  calculateEnsembleScore(results) {
    let weightedScore = 0;
    
    results.forEach(result => {
      const weight = ML_CONFIG.featureWeights[
        result.type === 'network' ? 'statistical' :
        result.type === 'process' ? 'behavioral' :
        result.type === 'behavior' ? 'temporal' : 'contextual'
      ] || 0.25;
      
      weightedScore += result.score * weight;
    });
    
    return Math.min(weightedScore, 1.0);
  }

  /**
   * Evaluate if anomaly might be a zero-day exploit
   */
  evaluateZeroDayPotential(results, ensembleScore) {
    // Criteria for zero-day classification:
    // 1. High anomaly score across multiple models
    // 2. Multiple anomalous features
    // 3. No known signature match
    // 4. Sophisticated evasion techniques
    
    const multiModelDetection = results.filter(r => r.anomaly).length >= 2;
    const highScore = ensembleScore >= ML_CONFIG.confidenceLevels.high;
    const manyAnomalousFeatures = results.some(r => 
      r.anomalousFeatures && r.anomalousFeatures.length >= 5
    );
    
    const zeroDayScore = 
      (multiModelDetection ? 0.4 : 0) +
      (highScore ? 0.3 : 0) +
      (manyAnomalousFeatures ? 0.3 : 0);
    
    if (zeroDayScore >= 0.7) {
      this.zeroDayCandidates.push({
        timestamp: new Date().toISOString(),
        ensembleScore,
        results,
        zeroDayScore
      });
    }
    
    return {
      isLikely: zeroDayScore >= 0.7,
      score: zeroDayScore,
      indicators: {
        multiModelDetection,
        highScore,
        manyAnomalousFeatures
      }
    };
  }

  /**
   * Get ensemble recommendation
   */
  getEnsembleRecommendation(ensembleScore, zeroDayPotential) {
    if (zeroDayPotential.isLikely) {
      return {
        action: 'immediate_quarantine',
        severity: 'critical',
        message: '🚨 ZERO-DAY EXPLOIT SUSPECTED - Immediate action required',
        priority: 0,
        autoResponse: true,
        alertSecurity: true,
        createForensics: true
      };
    }
    
    if (ensembleScore >= ML_CONFIG.confidenceLevels.high) {
      return {
        action: 'block_and_alert',
        severity: 'critical',
        message: 'Critical anomaly detected - potential unknown threat',
        priority: 1,
        autoResponse: true,
        alertSecurity: true
      };
    }
    
    if (ensembleScore >= ML_CONFIG.confidenceLevels.medium) {
      return {
        action: 'monitor_closely',
        severity: 'high',
        message: 'Significant anomaly - enhanced monitoring active',
        priority: 2,
        autoResponse: false,
        alertSecurity: false
      };
    }
    
    return {
      action: 'continue_monitoring',
      severity: 'low',
      message: 'Minor deviation from baseline',
      priority: 3,
      autoResponse: false,
      alertSecurity: false
    };
  }

  /**
   * Record anomaly for analysis
   */
  recordAnomaly(type, data, prediction) {
    this.detectionHistory.push({
      type,
      timestamp: new Date().toISOString(),
      data,
      prediction,
      score: prediction.score,
      confidence: prediction.confidence
    });
    
    // Maintain history size
    if (this.detectionHistory.length > 1000) {
      this.detectionHistory.shift();
    }
    
    // Auto-learning
    if (this.autoLearnEnabled && prediction.confidence < 0.5) {
      this.updateBaselineWithFeedback(type, data, false);
    }
  }

  /**
   * Update baseline with feedback (reduces false positives)
   */
  updateBaselineWithFeedback(type, data, isThreat) {
    if (!isThreat) {
      // This was a false positive, update baseline
      if (type === 'network') {
        this.baseline.updateBaseline('network', {
          avgPacketSize: data.size,
          avgRequestRate: 1
        });
      } else if (type === 'process') {
        this.baseline.updateBaseline('process', {
          normalCPUUsage: data.cpuUsage,
          normalMemoryUsage: data.memoryUsage
        });
      }
    }
  }

  /**
   * Get zero-day candidates for analysis
   */
  getZeroDayCandidates() {
    return this.zeroDayCandidates
      .sort((a, b) => b.zeroDayScore - a.zeroDayScore)
      .slice(0, 20);
  }

  /**
   * Get detection statistics (Enhanced with Deep Learning metrics)
   */
  getStatistics() {
    const totalDetections = this.detectionHistory.length;
    const anomalyCount = this.detectionHistory.filter(d => d.prediction.anomaly).length;
    const zeroDayCount = this.zeroDayCandidates.length;
    
    const avgScore = totalDetections > 0
      ? this.detectionHistory.reduce((sum, d) => sum + d.score, 0) / totalDetections
      : 0;
    
    const avgConfidence = totalDetections > 0
      ? this.detectionHistory.reduce((sum, d) => sum + d.confidence, 0) / totalDetections
      : 0;
    
    return {
      totalDetections,
      anomalyCount,
      zeroDayCount,
      anomalyRate: totalDetections > 0 ? (anomalyCount / totalDetections * 100).toFixed(2) : 0,
      avgScore: avgScore.toFixed(3),
      avgConfidence: avgConfidence.toFixed(3),
      
      modelsStatus: {
        // Statistical models
        network: this.networkModel.trained,
        process: this.processModel.trained,
        behavior: this.behaviorModel.trained,
        
        // Traditional ML
        isolationForest: this.isolationForest.trained,
        randomForest: this.randomForest.trained,
        gradientBoosting: this.gradientBoosting.trained,
        temporal: this.temporalAnalyzer.trained,
        
        // Deep Learning
        deepNN: this.deepNN.trained,
        autoEncoder: this.autoEncoder.trained,
        lstm: this.lstm.trained
      },
      
      modelPerformance: this.modelPerformance,
      
      advancedFeatures: {
        ensembleVoting: ML_CONFIG.ensemble.votingStrategy,
        
        // Traditional ML
        isolationForestTrees: ML_CONFIG.isolationForest.numTrees,
        randomForestTrees: ML_CONFIG.randomForest.numTrees,
        gradientBoostingEstimators: ML_CONFIG.gradientBoosting.numEstimators,
        temporalSequenceLength: ML_CONFIG.lstm.sequenceLength,
        
        // Deep Learning
        deepNNArchitecture: this.deepNN.layerSizes.join('→'),
        autoEncoderCompression: `${this.autoEncoder.inputSize}→${this.autoEncoder.encodingSize}→${this.autoEncoder.inputSize}`,
        lstmArchitecture: `${this.lstm.inputSize}→${this.lstm.hiddenSize}×${this.lstm.numLayers}`,
        
        // Data
        recentSamplesCount: this.recentSamples.length,
        eventSequencesCount: this.eventSequences.length
      },
      
      threatIntelligence: {
        iocCount: this.threatIntel.iocDatabase.size,
        knownPatterns: Object.keys(this.threatIntel.knownAttackPatterns).length,
        attackChains: this.threatIntel.attackChains.length
      }
    };
  }

  /**
   * Export model for persistence (Enhanced with Deep Learning)
   */
  exportModels() {
    return {
      network: {
        mean: this.networkModel.mean,
        stdDev: this.networkModel.stdDev,
        trained: this.networkModel.trained
      },
      process: {
        mean: this.processModel.mean,
        stdDev: this.processModel.stdDev,
        trained: this.processModel.trained
      },
      behavior: {
        mean: this.behaviorModel.mean,
        stdDev: this.behaviorModel.stdDev,
        trained: this.behaviorModel.trained
      },
      baseline: this.baseline,
      
      // Deep Learning models (weights and biases)
      deepNN: {
        weights: this.deepNN.weights,
        biases: this.deepNN.biases,
        layerSizes: this.deepNN.layerSizes,
        trained: this.deepNN.trained
      },
      autoEncoder: {
        encoderWeights: this.autoEncoder.encoderWeights,
        decoderWeights: this.autoEncoder.decoderWeights,
        encoderBias: this.autoEncoder.encoderBias,
        decoderBias: this.autoEncoder.decoderBias,
        threshold: this.autoEncoder.threshold,
        trained: this.autoEncoder.trained
      },
      
      // Threat Intelligence
      iocDatabase: Array.from(this.threatIntel.iocDatabase.entries()),
      
      // Model performance
      modelPerformance: this.modelPerformance
    };
  }

  /**
   * Import model from saved state (Enhanced)
   */
  importModels(modelData) {
    if (modelData.network) {
      Object.assign(this.networkModel, modelData.network);
    }
    if (modelData.process) {
      Object.assign(this.processModel, modelData.process);
    }
    if (modelData.behavior) {
      Object.assign(this.behaviorModel, modelData.behavior);
    }
    if (modelData.baseline) {
      Object.assign(this.baseline, modelData.baseline);
    }
    
    // Import Deep Learning models
    if (modelData.deepNN) {
      Object.assign(this.deepNN, modelData.deepNN);
    }
    if (modelData.autoEncoder) {
      Object.assign(this.autoEncoder, modelData.autoEncoder);
    }
    
    // Import Threat Intelligence
    if (modelData.iocDatabase) {
      this.threatIntel.iocDatabase = new Map(modelData.iocDatabase);
    }
    
    // Import performance metrics
    if (modelData.modelPerformance) {
      this.modelPerformance = modelData.modelPerformance;
    }
  }

  /**
   * Online learning - incrementally update models with new data
   */
  onlineUpdate(sample, label, learningRate = 0.01) {
    // Update Deep Neural Network
    if (this.deepNN.trained) {
      const input = this.deepNN.featuresToArray(sample);
      this.deepNN.backward(input, label);
    }
    
    // Update statistical models
    const type = sample.type || 'network';
    if (type === 'network' && this.networkModel.trained) {
      this.incrementalUpdate(this.networkModel, sample, learningRate);
    } else if (type === 'process' && this.processModel.trained) {
      this.incrementalUpdate(this.processModel, sample, learningRate);
    } else if (type === 'behavior' && this.behaviorModel.trained) {
      this.incrementalUpdate(this.behaviorModel, sample, learningRate);
    }
  }

  /**
   * Incremental update for statistical models
   */
  incrementalUpdate(model, sample, learningRate) {
    Object.keys(sample).forEach(feature => {
      if (model.mean[feature] !== undefined) {
        // Exponential moving average
        model.mean[feature] = (1 - learningRate) * model.mean[feature] + learningRate * sample[feature];
        
        // Update standard deviation
        const deviation = sample[feature] - model.mean[feature];
        const variance = model.stdDev[feature] * model.stdDev[feature];
        const newVariance = (1 - learningRate) * variance + learningRate * deviation * deviation;
        model.stdDev[feature] = Math.sqrt(newVariance);
      }
    });
  }

  /**
   * Adaptive threshold adjustment based on false positive rate
   */
  adaptThreshold(falsePositiveRate) {
    if (falsePositiveRate > 0.1) {
      // Too many false positives, increase threshold
      ML_CONFIG.anomalyThreshold = Math.min(ML_CONFIG.anomalyThreshold + 0.05, 0.95);
      console.log(`📈 Increased anomaly threshold to ${ML_CONFIG.anomalyThreshold.toFixed(2)}`);
    } else if (falsePositiveRate < 0.02) {
      // Very few false positives, can be more sensitive
      ML_CONFIG.anomalyThreshold = Math.max(ML_CONFIG.anomalyThreshold - 0.02, 0.50);
      console.log(`📉 Decreased anomaly threshold to ${ML_CONFIG.anomalyThreshold.toFixed(2)}`);
    }
  }

  /**
   * Explainable AI - Get feature importance and decision explanation
   */
  explainPrediction(features, prediction) {
    const explanation = {
      decision: prediction.anomaly ? 'ANOMALY' : 'NORMAL',
      confidence: prediction.confidence,
      score: prediction.score,
      contributingFactors: [],
      modelContributions: {},
      featureImportance: {},
      recommendations: []
    };

    // Feature importance from Random Forest
    if (this.randomForest.trained && this.randomForest.featureImportance) {
      explanation.featureImportance = this.randomForest.featureImportance;
    }

    // Analyze which features contributed most to the decision
    Object.entries(features).forEach(([feature, value]) => {
      const importance = explanation.featureImportance[feature] || 0.5;
      
      if (value > 0.7 && importance > 0.5) {
        explanation.contributingFactors.push({
          feature,
          value: value.toFixed(3),
          importance: importance.toFixed(3),
          impact: (value * importance).toFixed(3),
          description: this.getFeatureDescription(feature, value)
        });
      }
    });

    // Sort by impact
    explanation.contributingFactors.sort((a, b) => b.impact - a.impact);

    // Model contributions
    Object.entries(prediction.predictions).forEach(([model, pred]) => {
      if (pred && pred.score !== undefined) {
        explanation.modelContributions[model] = {
          score: pred.score.toFixed(3),
          voted: pred.anomaly ? 'ANOMALY' : 'NORMAL',
          confidence: (pred.confidence || 0).toFixed(3)
        };
      }
    });

    // Generate recommendations
    if (prediction.anomaly) {
      explanation.recommendations.push('Quarantine suspected file/process immediately');
      explanation.recommendations.push('Capture network traffic for forensic analysis');
      
      if (prediction.threatIntelMatch) {
        explanation.recommendations.push(
          `Known threat pattern: ${prediction.threatIntelMatch.pattern}`
        );
      }
      
      if (prediction.score > 0.9) {
        explanation.recommendations.push('HIGH PRIORITY: Likely zero-day exploit');
        explanation.recommendations.push('Create memory dump for malware analysis');
      }
    }

    return explanation;
  }

  /**
   * Get human-readable feature description
   */
  getFeatureDescription(feature, value) {
    const descriptions = {
      packetSizeRatio: value > 0.8 ? 'Unusually large packet size' : 'Large packet',
      portRiskScore: value > 0.7 ? 'High-risk port detected' : 'Suspicious port',
      payloadEntropy: value > 0.7 ? 'Highly encrypted/random payload' : 'Encrypted data',
      cpuAnomalyScore: value > 0.7 ? 'Excessive CPU usage' : 'High CPU usage',
      memoryAnomalyScore: value > 0.7 ? 'Excessive memory usage' : 'High memory usage',
      commandLineComplexity: value > 0.8 ? 'Highly suspicious command line' : 'Complex command',
      injectionIndicators: value > 0.7 ? 'Code injection detected' : 'Injection signs',
      privilegeEscalation: value > 0.6 ? 'Privilege escalation attempt' : 'Elevated privileges',
      lateralMovementIndicator: value > 0.7 ? 'Lateral movement detected' : 'Network spread',
      dataExfiltrationRisk: value > 0.8 ? 'Data exfiltration in progress' : 'Data transfer'
    };
    
    return descriptions[feature] || `${feature}: ${value.toFixed(2)}`;
  }

  /**
   * Get threat trend analysis
   */
  getThreatTrends(hours = 24) {
    const cutoff = Date.now() - hours * 60 * 60 * 1000;
    const recentDetections = this.detectionHistory.filter(d => 
      new Date(d.timestamp).getTime() > cutoff
    );

    const trends = {
      timeline: [],
      topThreats: new Map(),
      severityDistribution: { critical: 0, high: 0, medium: 0, low: 0 },
      attackVectors: { network: 0, process: 0, behavior: 0 }
    };

    // Group by hour
    const hourly = new Map();
    recentDetections.forEach(detection => {
      const hour = new Date(detection.timestamp).setMinutes(0, 0, 0);
      hourly.set(hour, (hourly.get(hour) || 0) + 1);
      
      // Count attack vectors
      trends.attackVectors[detection.type]++;
      
      // Severity distribution
      const severity = detection.prediction.recommendation?.severity || 'low';
      trends.severityDistribution[severity]++;
    });

    // Convert to timeline
    hourly.forEach((count, timestamp) => {
      trends.timeline.push({
        timestamp: new Date(timestamp).toISOString(),
        count
      });
    });

    trends.timeline.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    return trends;
  }
}

// ==================== SINGLETON INSTANCE ====================

const mlAnomalyDetector = new EnsembleAnomalyDetector();

// ==================== EXPORTS ====================

export default mlAnomalyDetector;

export {
  ML_CONFIG,
  BaselineProfile,
  FeatureExtractor,
  AnomalyDetectionModel,
  EnsembleAnomalyDetector
};
