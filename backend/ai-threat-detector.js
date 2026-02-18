/**
 * AI-Powered Threat Detection Engine
 * Advanced machine learning-based network threat analysis with neural network simulation
 */

class AIThreatDetector {
  constructor() {
    this.anomalyThreshold = 0.7;
    this.learningRate = 0.01;
    this.trafficPatterns = new Map();
    this.threatScores = new Map();
    this.behavioralProfiles = new Map();
    
    // Neural network layers (simulated)
    this.neuralNetwork = {
      inputLayer: 15, // 15 features
      hiddenLayers: [32, 16, 8], // 3 hidden layers
      outputLayer: 1, // Threat probability
      weights: null, // Will be initialized after
      biases: null // Will be initialized after
    };
    
    // Initialize weights and biases after neuralNetwork is defined
    this.neuralNetwork.weights = this.initializeWeights();
    this.neuralNetwork.biases = this.initializeBiases();
    
    // Advanced feature extraction
    this.featureExtractor = {
      entropy: true,
      timeSeries: true,
      graphAnalysis: true,
      clustering: true
    };
    
    // Time-series anomaly detection
    this.timeSeriesData = new Map();
    this.seasonalPatterns = new Map();
    
    // Graph-based threat correlation
    this.connectionGraph = new Map();
    
    // Threat intelligence feed (simulated)
    this.threatIntelligence = {
      knownMaliciousIPs: new Set(),
      knownMaliciousPatterns: [],
      lastUpdate: Date.now()
    };
    
    // Model performance tracking
    this.performance = {
      truePositives: 0,
      falsePositives: 0,
      trueNegatives: 0,
      falseNegatives: 0,
      accuracy: 0,
      precision: 0,
      recall: 0,
      f1Score: 0
    };
    
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
   * Initialize neural network weights
   */
  initializeWeights() {
    const weights = [];
    const layers = [this.neuralNetwork.inputLayer, ...this.neuralNetwork.hiddenLayers, this.neuralNetwork.outputLayer];
    
    for (let i = 0; i < layers.length - 1; i++) {
      const layerWeights = [];
      for (let j = 0; j < layers[i]; j++) {
        const neuronWeights = [];
        for (let k = 0; k < layers[i + 1]; k++) {
          // Xavier initialization
          neuronWeights.push((Math.random() - 0.5) * Math.sqrt(2 / layers[i]));
        }
        layerWeights.push(neuronWeights);
      }
      weights.push(layerWeights);
    }
    
    return weights;
  }

  /**
   * Initialize biases
   */
  initializeBiases() {
    const biases = [];
    const layers = [...this.neuralNetwork.hiddenLayers, this.neuralNetwork.outputLayer];
    
    for (const layerSize of layers) {
      biases.push(new Array(layerSize).fill(0));
    }
    
    return biases;
  }

  /**
   * Extract advanced features from connection
   */
  extractFeatures(connection) {
    const features = [];
    
    // Basic features (normalized)
    features.push(connection.sourcePort / 65535);
    features.push(connection.destPort / 65535);
    features.push((connection.bytes || 0) / 100000);
    features.push((connection.packets || 0) / 1000);
    
    // Protocol encoding (one-hot)
    features.push(connection.protocol === 'tcp' ? 1 : 0);
    features.push(connection.protocol === 'udp' ? 1 : 0);
    features.push(connection.protocol === 'icmp' ? 1 : 0);
    
    // Entropy of data (simulated)
    features.push(this.calculateEntropy(connection));
    
    // Time-based features
    const hour = new Date(connection.timestamp).getHours();
    features.push(Math.sin(2 * Math.PI * hour / 24)); // Cyclical time encoding
    features.push(Math.cos(2 * Math.PI * hour / 24));
    
    // Historical features
    const history = this.timeSeriesData.get(connection.sourceIP) || [];
    features.push(history.length / 1000); // Connection frequency
    features.push(this.calculateMovingAverage(history, 'bytes'));
    features.push(this.calculateStandardDeviation(history, 'bytes'));
    
    // Graph features
    features.push(this.calculateNodeDegree(connection.sourceIP));
    features.push(this.calculateClusteringCoefficient(connection.sourceIP));
    
    return features;
  }

  /**
   * Calculate Shannon entropy
   */
  calculateEntropy(connection) {
    if (!connection.payload) return 0.5;
    
    const freq = new Map();
    for (const char of connection.payload || '') {
      freq.set(char, (freq.get(char) || 0) + 1);
    }
    
    let entropy = 0;
    const len = connection.payload.length;
    
    for (const count of freq.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    
    return Math.min(entropy / 8, 1); // Normalize
  }

  /**
   * Forward propagation through neural network
   */
  forwardPropagate(features) {
    let activations = features;
    
    for (let layer = 0; layer < this.neuralNetwork.weights.length; layer++) {
      const nextActivations = [];
      const weights = this.neuralNetwork.weights[layer];
      const biases = this.neuralNetwork.biases[layer];
      
      for (let j = 0; j < weights[0].length; j++) {
        let sum = biases[j];
        for (let i = 0; i < activations.length; i++) {
          sum += activations[i] * weights[i][j];
        }
        
        // ReLU activation for hidden layers, sigmoid for output
        const activation = layer === this.neuralNetwork.weights.length - 1
          ? 1 / (1 + Math.exp(-sum)) // Sigmoid
          : Math.max(0, sum); // ReLU
        
        nextActivations.push(activation);
      }
      
      activations = nextActivations;
    }
    
    return activations[0]; // Output probability
  }

  /**
   * Train neural network with backpropagation (simplified)
   */
  trainNetwork(features, actualThreat) {
    const prediction = this.forwardPropagate(features);
    const error = actualThreat - prediction;
    
    // Gradient descent weight update (simplified)
    for (let layer = this.neuralNetwork.weights.length - 1; layer >= 0; layer--) {
      for (let i = 0; i < this.neuralNetwork.weights[layer].length; i++) {
        for (let j = 0; j < this.neuralNetwork.weights[layer][i].length; j++) {
          const gradient = error * features[i] * this.learningRate;
          this.neuralNetwork.weights[layer][i][j] += gradient;
        }
      }
    }
    
    return { prediction, error, loss: error * error };
  }

  /**
   * Advanced anomaly detection with neural network
   */
  detectAnomalyAdvanced(connection) {
    // Extract features
    const features = this.extractFeatures(connection);
    
    // Get neural network prediction
    const nnThreatScore = this.forwardPropagate(features);
    
    // Combine with rule-based detection
    const ruleBasedAnalysis = this.analyzeConnection(connection);
    
    // Ensemble method: weighted average
    const ensembleThreatScore = (nnThreatScore * 0.6) + (ruleBasedAnalysis.threatScore * 0.4);
    
    // Time-series anomaly detection
    const timeSeriesAnomaly = this.detectTimeSeriesAnomaly(connection);
    
    // Graph-based anomaly detection
    const graphAnomaly = this.detectGraphAnomaly(connection);
    
    // Final threat score with all methods
    const finalThreatScore = Math.max(
      ensembleThreatScore,
      timeSeriesAnomaly * 0.3,
      graphAnomaly * 0.3
    );
    
    return {
      ...ruleBasedAnalysis,
      threatScore: finalThreatScore,
      nnPrediction: nnThreatScore,
      timeSeriesAnomaly,
      graphAnomaly,
      features: features.slice(0, 5), // Return first 5 features for debugging
      modelType: 'ensemble',
      confidence: this.calculateConfidence(finalThreatScore, ensembleThreatScore, timeSeriesAnomaly, graphAnomaly)
    };
  }

  /**
   * Time-series anomaly detection
   */
  detectTimeSeriesAnomaly(connection) {
    const key = connection.sourceIP;
    const history = this.timeSeriesData.get(key) || [];
    
    // Add current data point
    history.push({
      timestamp: connection.timestamp,
      bytes: connection.bytes || 0,
      packets: connection.packets || 0,
      port: connection.destPort
    });
    
    // Keep last 1000 data points
    if (history.length > 1000) {
      history.shift();
    }
    
    this.timeSeriesData.set(key, history);
    
    if (history.length < 10) return 0;
    
    // Calculate moving statistics
    const recentBytes = history.slice(-10).map(h => h.bytes);
    const mean = recentBytes.reduce((a, b) => a + b, 0) / recentBytes.length;
    const stdDev = Math.sqrt(
      recentBytes.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / recentBytes.length
    );
    
    // Z-score anomaly detection
    const zScore = Math.abs((connection.bytes - mean) / (stdDev || 1));
    
    // Seasonal pattern detection
    const hourlyPattern = this.getSeasonalPattern(key, new Date(connection.timestamp).getHours());
    const seasonalAnomaly = Math.abs(connection.bytes - hourlyPattern) / (hourlyPattern || 1);
    
    // Combine anomalies
    const anomalyScore = Math.min((zScore / 3) + (seasonalAnomaly * 0.3), 1);
    
    return anomalyScore;
  }

  /**
   * Graph-based anomaly detection
   */
  detectGraphAnomaly(connection) {
    const sourceIP = connection.sourceIP;
    const destIP = connection.destIP;
    
    // Build connection graph
    if (!this.connectionGraph.has(sourceIP)) {
      this.connectionGraph.set(sourceIP, new Set());
    }
    this.connectionGraph.get(sourceIP).add(destIP);
    
    // Calculate graph metrics
    const degree = this.calculateNodeDegree(sourceIP);
    const clustering = this.calculateClusteringCoefficient(sourceIP);
    
    // Anomaly indicators
    let anomalyScore = 0;
    
    // High degree (connects to many hosts) - potential scanner
    if (degree > 50) {
      anomalyScore += Math.min(degree / 100, 0.5);
    }
    
    // Low clustering coefficient - unusual connection pattern
    if (clustering < 0.1 && degree > 10) {
      anomalyScore += 0.3;
    }
    
    // Check for hub behavior (connects to many but receives few connections)
    const inDegree = this.calculateInDegree(sourceIP);
    if (degree > 20 && inDegree < 3) {
      anomalyScore += 0.4;
    }
    
    return Math.min(anomalyScore, 1);
  }

  /**
   * Calculate moving average
   */
  calculateMovingAverage(history, field) {
    if (history.length === 0) return 0;
    const recent = history.slice(-10);
    return recent.reduce((sum, item) => sum + (item[field] || 0), 0) / recent.length / 100000;
  }

  /**
   * Calculate standard deviation
   */
  calculateStandardDeviation(history, field) {
    if (history.length < 2) return 0;
    const recent = history.slice(-10);
    const mean = recent.reduce((sum, item) => sum + (item[field] || 0), 0) / recent.length;
    const variance = recent.reduce((sum, item) => sum + Math.pow((item[field] || 0) - mean, 2), 0) / recent.length;
    return Math.sqrt(variance) / 100000;
  }

  /**
   * Get seasonal pattern
   */
  getSeasonalPattern(ip, hour) {
    const key = `${ip}_${hour}`;
    const pattern = this.seasonalPatterns.get(key) || { count: 0, avgBytes: 0 };
    return pattern.avgBytes;
  }

  /**
   * Update seasonal patterns
   */
  updateSeasonalPattern(ip, hour, bytes) {
    const key = `${ip}_${hour}`;
    const pattern = this.seasonalPatterns.get(key) || { count: 0, avgBytes: 0 };
    
    pattern.count++;
    pattern.avgBytes = (pattern.avgBytes * (pattern.count - 1) + bytes) / pattern.count;
    
    this.seasonalPatterns.set(key, pattern);
  }

  /**
   * Calculate node degree in connection graph
   */
  calculateNodeDegree(ip) {
    const connections = this.connectionGraph.get(ip);
    return connections ? connections.size / 100 : 0; // Normalized
  }

  /**
   * Calculate in-degree (how many nodes connect to this IP)
   */
  calculateInDegree(ip) {
    let inDegree = 0;
    for (const [, connections] of this.connectionGraph) {
      if (connections.has(ip)) {
        inDegree++;
      }
    }
    return inDegree;
  }

  /**
   * Calculate clustering coefficient
   */
  calculateClusteringCoefficient(ip) {
    const neighbors = this.connectionGraph.get(ip);
    if (!neighbors || neighbors.size < 2) return 0;
    
    let edges = 0;
    const neighborsArray = Array.from(neighbors);
    
    for (let i = 0; i < neighborsArray.length; i++) {
      for (let j = i + 1; j < neighborsArray.length; j++) {
        const neighborConnections = this.connectionGraph.get(neighborsArray[i]);
        if (neighborConnections && neighborConnections.has(neighborsArray[j])) {
          edges++;
        }
      }
    }
    
    const possibleEdges = (neighbors.size * (neighbors.size - 1)) / 2;
    return possibleEdges > 0 ? edges / possibleEdges : 0;
  }

  /**
   * Calculate confidence score
   */
  calculateConfidence(finalScore, ensembleScore, timeSeriesAnomaly, graphAnomaly) {
    // Agreement between different methods increases confidence
    const scores = [ensembleScore, timeSeriesAnomaly, graphAnomaly].filter(s => s > 0);
    const variance = scores.length > 1
      ? scores.reduce((sum, s) => sum + Math.pow(s - finalScore, 2), 0) / scores.length
      : 0;
    
    const agreement = Math.exp(-variance * 10); // High agreement = high confidence
    const dataPoints = Math.min((this.timeSeriesData.get('any')?.length || 0) / 100, 1);
    
    return Math.min((agreement * 0.7 + dataPoints * 0.3) * 100, 100);
  }

  /**
   * Update model performance metrics
   */
  updatePerformance(predicted, actual) {
    if (predicted && actual) {
      this.performance.truePositives++;
    } else if (predicted && !actual) {
      this.performance.falsePositives++;
    } else if (!predicted && actual) {
      this.performance.falseNegatives++;
    } else {
      this.performance.trueNegatives++;
    }
    
    const total = this.performance.truePositives + this.performance.falsePositives +
                  this.performance.trueNegatives + this.performance.falseNegatives;
    
    if (total > 0) {
      this.performance.accuracy = ((this.performance.truePositives + this.performance.trueNegatives) / total) * 100;
      
      const precisionDenom = this.performance.truePositives + this.performance.falsePositives;
      this.performance.precision = precisionDenom > 0
        ? (this.performance.truePositives / precisionDenom) * 100
        : 0;
      
      const recallDenom = this.performance.truePositives + this.performance.falseNegatives;
      this.performance.recall = recallDenom > 0
        ? (this.performance.truePositives / recallDenom) * 100
        : 0;
      
      this.performance.f1Score = (this.performance.precision + this.performance.recall) > 0
        ? 2 * (this.performance.precision * this.performance.recall) / (this.performance.precision + this.performance.recall)
        : 0;
    }
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
                      (this.threatScores.size || 1),
      neuralNetwork: {
        architecture: `${this.neuralNetwork.inputLayer}-${this.neuralNetwork.hiddenLayers.join('-')}-${this.neuralNetwork.outputLayer}`,
        totalWeights: this.neuralNetwork.weights.reduce((sum, layer) => 
          sum + layer.reduce((s, neuron) => s + neuron.length, 0), 0),
        layers: this.neuralNetwork.weights.length
      },
      timeSeriesTracking: this.timeSeriesData.size,
      graphNodes: this.connectionGraph.size,
      graphEdges: Array.from(this.connectionGraph.values()).reduce((sum, set) => sum + set.size, 0),
      seasonalPatterns: this.seasonalPatterns.size,
      performance: {
        ...this.performance,
        accuracy: this.performance.accuracy.toFixed(2) + '%',
        precision: this.performance.precision.toFixed(2) + '%',
        recall: this.performance.recall.toFixed(2) + '%',
        f1Score: this.performance.f1Score.toFixed(2) + '%'
      }
    };
  }

  /**
   * Get threat intelligence summary
   */
  getThreatIntelligence() {
    return {
      knownMaliciousIPs: this.threatIntelligence.knownMaliciousIPs.size,
      lastUpdate: new Date(this.threatIntelligence.lastUpdate).toISOString(),
      topThreats: this.getTopThreats(10)
    };
  }

  /**
   * Get top threats
   */
  getTopThreats(limit = 10) {
    return Array.from(this.threatScores.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([ip, score]) => ({
        ip,
        threatScore: score.toFixed(3),
        reputation: score < 0.3 ? 'good' : score < 0.7 ? 'suspicious' : 'malicious',
        connections: this.behavioralProfiles.get(ip)?.connectionCount || 0
      }));
  }
}

module.exports = new AIThreatDetector();
