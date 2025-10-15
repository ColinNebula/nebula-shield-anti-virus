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
    
    this.baseline = new BaselineProfile();
    this.featureExtractor = new FeatureExtractor();
    
    this.detectionHistory = [];
    this.zeroDayCandidates = [];
    this.autoLearnEnabled = true;
    this.recentSamples = []; // For temporal analysis
    this.modelPerformance = {
      isolationForest: { accuracy: 0, detections: 0 },
      randomForest: { accuracy: 0, detections: 0 },
      gradientBoosting: { accuracy: 0, detections: 0 },
      temporal: { accuracy: 0, detections: 0 },
      statistical: { accuracy: 0, detections: 0 }
    };
  }

  /**
   * Train all models with historical data (Enhanced with advanced ML)
   */
  async trainModels(trainingData) {
    console.log('🧠 Training Enhanced ML anomaly detection models...');
    
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
    
    const results = {
      // Original statistical models
      network: this.networkModel.train(networkSamples),
      process: this.processModel.train(processSamples),
      behavior: this.behaviorModel.train(behaviorSamples),
      
      // Advanced ML models
      isolationForest: this.isolationForest.train(allSamples),
      randomForest: this.randomForest.train(allSamples, labels),
      gradientBoosting: this.gradientBoosting.train(allSamples, labels),
      temporal: this.temporalAnalyzer.train(allSamples)
    };
    
    console.log('✅ Enhanced model training complete:', results);
    return results;
  }

  /**
   * Ensemble prediction combining all models
   */
  ensemblePredict(features, type = 'network') {
    const predictions = {
      statistical: null,
      isolationForest: null,
      randomForest: null,
      gradientBoosting: null,
      temporal: null
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
    
    // Temporal analysis (if enough history)
    if (this.recentSamples.length >= ML_CONFIG.lstm.sequenceLength) {
      predictions.temporal = this.temporalAnalyzer.predict(this.recentSamples);
    } else {
      predictions.temporal = { anomaly: false, score: 0 };
    }

    // Ensemble voting strategy
    const weights = ML_CONFIG.ensemble.modelWeights;
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

    const finalScore = weightedScore / totalWeight;
    const votingScore = anomalyVotes / totalVotes;

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
   * Detect anomalies in network traffic (Enhanced)
   */
  detectNetworkAnomaly(packet) {
    const features = this.featureExtractor.extractNetworkFeatures(packet);
    
    // Add to recent samples for temporal analysis
    this.recentSamples.push(features);
    if (this.recentSamples.length > ML_CONFIG.lstm.sequenceLength * 2) {
      this.recentSamples.shift();
    }
    
    // Get ensemble prediction
    const prediction = this.ensemblePredict(features, 'network');
    
    if (prediction.anomaly) {
      this.recordAnomaly('network', packet, prediction);
      this.updateModelPerformance(prediction);
    }
    
    return {
      ...prediction,
      type: 'network',
      data: packet,
      detectedBy: Object.entries(prediction.predictions)
        .filter(([_, pred]) => pred?.anomaly)
        .map(([model, _]) => model)
    };
  }

  /**
   * Detect anomalies in process behavior (Enhanced)
   */
  detectProcessAnomaly(process) {
    const features = this.featureExtractor.extractProcessFeatures(process);
    
    this.recentSamples.push(features);
    if (this.recentSamples.length > ML_CONFIG.lstm.sequenceLength * 2) {
      this.recentSamples.shift();
    }
    
    const prediction = this.ensemblePredict(features, 'process');
    
    if (prediction.anomaly) {
      this.recordAnomaly('process', process, prediction);
      this.updateModelPerformance(prediction);
    }
    
    return {
      ...prediction,
      type: 'process',
      data: process,
      detectedBy: Object.entries(prediction.predictions)
        .filter(([_, pred]) => pred?.anomaly)
        .map(([model, _]) => model)
    };
  }

  /**
   * Detect anomalies in user/system behavior (Enhanced)
   */
  detectBehavioralAnomaly(event) {
    const features = this.featureExtractor.extractBehavioralFeatures(event);
    
    this.recentSamples.push(features);
    if (this.recentSamples.length > ML_CONFIG.lstm.sequenceLength * 2) {
      this.recentSamples.shift();
    }
    
    const prediction = this.ensemblePredict(features, 'behavior');
    
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
   * Get detection statistics
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
        network: this.networkModel.trained,
        process: this.processModel.trained,
        behavior: this.behaviorModel.trained,
        isolationForest: this.isolationForest.trained,
        randomForest: this.randomForest.trained,
        gradientBoosting: this.gradientBoosting.trained,
        temporal: this.temporalAnalyzer.trained
      },
      modelPerformance: this.modelPerformance,
      advancedFeatures: {
        ensembleVoting: ML_CONFIG.ensemble.votingStrategy,
        isolationForestTrees: ML_CONFIG.isolationForest.numTrees,
        randomForestTrees: ML_CONFIG.randomForest.numTrees,
        gradientBoostingEstimators: ML_CONFIG.gradientBoosting.numEstimators,
        temporalSequenceLength: ML_CONFIG.lstm.sequenceLength,
        recentSamplesCount: this.recentSamples.length
      }
    };
  }

  /**
   * Export model for persistence
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
      baseline: this.baseline
    };
  }

  /**
   * Import model from saved state
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
