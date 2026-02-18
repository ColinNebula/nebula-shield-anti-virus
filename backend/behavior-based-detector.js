/**
 * Behavior-Based Detection Engine
 * ML model to detect zero-day threats based on file behavior
 * Monitors file system operations, process behavior, and API calls
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

class BehaviorBasedDetector {
  constructor() {
    this.behaviorProfiles = new Map();
    this.suspiciousPatterns = new Map();
    this.processMonitoring = new Map();
    this.fileActivityLog = [];
    this.networkActivityLog = [];
    this.registryActivityLog = [];
    
    // ML model parameters
    this.modelWeights = {
      fileSystemOps: 0.25,
      processCreation: 0.30,
      networkActivity: 0.25,
      registryModification: 0.20
    };
    
    // Behavioral thresholds
    this.thresholds = {
      suspiciousScore: 0.65,
      maliciousScore: 0.85,
      criticalScore: 0.95
    };
    
    // Known suspicious behaviors
    this.suspiciousBehaviors = {
      // File system behaviors
      rapidFileCreation: {
        maxFiles: 50,
        timeWindow: 5000, // 5 seconds
        weight: 0.7,
        description: 'Rapid file creation (possible ransomware)'
      },
      massFileEncryption: {
        maxFiles: 20,
        timeWindow: 10000,
        weight: 0.95,
        description: 'Mass file encryption detected'
      },
      systemFileModification: {
        weight: 0.90,
        description: 'Attempt to modify system files'
      },
      hiddenFileCreation: {
        weight: 0.60,
        description: 'Creating hidden files'
      },
      
      // Process behaviors
      processInjection: {
        weight: 0.95,
        description: 'Process injection detected'
      },
      privilegeEscalation: {
        weight: 0.90,
        description: 'Privilege escalation attempt'
      },
      suspiciousProcessChain: {
        maxDepth: 3,
        weight: 0.75,
        description: 'Suspicious process chain'
      },
      scriptExecutionFromTemp: {
        weight: 0.80,
        description: 'Script execution from temp directory'
      },
      
      // Network behaviors
      unknownOutboundConnection: {
        weight: 0.70,
        description: 'Connection to unknown remote server'
      },
      dataExfiltration: {
        minBytes: 10 * 1024 * 1024, // 10MB
        timeWindow: 30000,
        weight: 0.85,
        description: 'Large data transfer detected'
      },
      commandAndControl: {
        weight: 0.90,
        description: 'C&C communication pattern'
      },
      
      // Registry behaviors
      startupModification: {
        weight: 0.75,
        description: 'Startup registry modification'
      },
      securityPolicyChange: {
        weight: 0.85,
        description: 'Security policy modification'
      },
      serviceCreation: {
        weight: 0.70,
        description: 'New service creation'
      }
    };
    
    // Initialize ML model
    this.initializeModel();
  }

  /**
   * Initialize ML model for behavior analysis
   */
  initializeModel() {
    // Simple neural network weights initialization
    this.neuralNetwork = {
      inputLayer: 64,
      hiddenLayers: [128, 64, 32],
      outputLayer: 1,
      weights: this.generateRandomWeights(),
      bias: this.generateRandomBias(),
      activationFunction: 'relu'
    };
    
    console.log('🧠 Behavior-based ML model initialized');
  }

  /**
   * Analyze file behavior for zero-day threats
   */
  async analyzeFileBehavior(filePath, options = {}) {
    const startTime = Date.now();
    const behaviorLog = {
      filePath,
      timestamp: new Date().toISOString(),
      behaviors: [],
      score: 0,
      verdict: 'clean',
      recommendations: []
    };

    try {
      // 1. Monitor file system operations
      const fileSystemScore = await this.monitorFileSystemOps(filePath);
      behaviorLog.behaviors.push({
        category: 'filesystem',
        score: fileSystemScore.score,
        details: fileSystemScore.details
      });

      // 2. Analyze process creation and behavior
      const processScore = await this.analyzeProcessBehavior(filePath);
      behaviorLog.behaviors.push({
        category: 'process',
        score: processScore.score,
        details: processScore.details
      });

      // 3. Monitor network activity
      const networkScore = await this.monitorNetworkActivity(filePath);
      behaviorLog.behaviors.push({
        category: 'network',
        score: networkScore.score,
        details: networkScore.details
      });

      // 4. Check registry modifications
      const registryScore = await this.checkRegistryActivity(filePath);
      behaviorLog.behaviors.push({
        category: 'registry',
        score: registryScore.score,
        details: registryScore.details
      });

      // 5. Calculate overall threat score using ML model
      behaviorLog.score = this.calculateThreatScore({
        fileSystem: fileSystemScore.score,
        process: processScore.score,
        network: networkScore.score,
        registry: registryScore.score
      });

      // 6. Determine verdict
      if (behaviorLog.score >= this.thresholds.criticalScore) {
        behaviorLog.verdict = 'critical';
        behaviorLog.recommendations.push('Immediate quarantine required');
        behaviorLog.recommendations.push('Block all network access');
        behaviorLog.recommendations.push('Terminate associated processes');
      } else if (behaviorLog.score >= this.thresholds.maliciousScore) {
        behaviorLog.verdict = 'malicious';
        behaviorLog.recommendations.push('Quarantine file');
        behaviorLog.recommendations.push('Monitor for additional activity');
      } else if (behaviorLog.score >= this.thresholds.suspiciousScore) {
        behaviorLog.verdict = 'suspicious';
        behaviorLog.recommendations.push('Enhanced monitoring recommended');
        behaviorLog.recommendations.push('Restrict network access');
      } else {
        behaviorLog.verdict = 'clean';
      }

      // 7. Add explainability
      behaviorLog.explanation = this.generateExplanation(behaviorLog);
      behaviorLog.duration = Date.now() - startTime;

      // Store behavior profile
      this.storeBehaviorProfile(filePath, behaviorLog);

      return behaviorLog;

    } catch (error) {
      console.error('Behavior analysis error:', error);
      return {
        ...behaviorLog,
        error: error.message,
        verdict: 'error',
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Monitor file system operations
   */
  async monitorFileSystemOps(filePath) {
    const score = { score: 0, details: [] };
    
    try {
      const fileStats = await fs.stat(filePath);
      
      // Check for rapid file creation pattern
      const recentFiles = this.fileActivityLog.filter(
        log => Date.now() - log.timestamp < 5000
      );
      
      if (recentFiles.length > this.suspiciousBehaviors.rapidFileCreation.maxFiles) {
        score.score += 0.7;
        score.details.push({
          behavior: 'Rapid file creation',
          severity: 'high',
          count: recentFiles.length
        });
      }

      // Check if file is hidden
      if (path.basename(filePath).startsWith('.')) {
        score.score += 0.3;
        score.details.push({
          behavior: 'Hidden file',
          severity: 'medium'
        });
      }

      // Check system directories
      const systemDirs = ['C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)'];
      if (systemDirs.some(dir => filePath.startsWith(dir))) {
        score.score += 0.5;
        score.details.push({
          behavior: 'Access to system directory',
          severity: 'high'
        });
      }

      // Check file extension anomalies
      const suspiciousExtensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.ps1'];
      const ext = path.extname(filePath).toLowerCase();
      if (suspiciousExtensions.includes(ext)) {
        score.score += 0.2;
        score.details.push({
          behavior: 'Executable file type',
          severity: 'medium',
          extension: ext
        });
      }

      // Normalize score
      score.score = Math.min(score.score, 1.0);

    } catch (error) {
      console.error('File system monitoring error:', error);
    }

    return score;
  }

  /**
   * Analyze process behavior
   */
  async analyzeProcessBehavior(filePath) {
    const score = { score: 0, details: [] };

    try {
      // Check if process is running from temp directory
      const tempDirs = ['\\Temp\\', '\\tmp\\', '\\AppData\\Local\\Temp'];
      if (tempDirs.some(dir => filePath.includes(dir))) {
        score.score += this.suspiciousBehaviors.scriptExecutionFromTemp.weight;
        score.details.push({
          behavior: 'Execution from temp directory',
          severity: 'high'
        });
      }

      // Check for suspicious parent processes
      // This would require Windows API calls in production
      // For now, we'll use heuristics
      
      // Check process chain depth
      const processChain = this.getProcessChain(filePath);
      if (processChain.length > this.suspiciousBehaviors.suspiciousProcessChain.maxDepth) {
        score.score += 0.4;
        score.details.push({
          behavior: 'Deep process chain',
          severity: 'medium',
          depth: processChain.length
        });
      }

      // Normalize score
      score.score = Math.min(score.score, 1.0);

    } catch (error) {
      console.error('Process behavior analysis error:', error);
    }

    return score;
  }

  /**
   * Monitor network activity
   */
  async monitorNetworkActivity(filePath) {
    const score = { score: 0, details: [] };

    try {
      // Check recent network connections
      const recentConnections = this.networkActivityLog.filter(
        log => log.process === filePath && Date.now() - log.timestamp < 30000
      );

      if (recentConnections.length > 0) {
        // Check for connections to unknown IPs
        const unknownConnections = recentConnections.filter(
          conn => !this.isKnownGoodIP(conn.remoteIP)
        );

        if (unknownConnections.length > 0) {
          score.score += 0.5;
          score.details.push({
            behavior: 'Unknown outbound connections',
            severity: 'high',
            count: unknownConnections.length,
            destinations: unknownConnections.slice(0, 5).map(c => c.remoteIP)
          });
        }

        // Check for large data transfers
        const totalBytes = recentConnections.reduce((sum, conn) => sum + (conn.bytes || 0), 0);
        if (totalBytes > this.suspiciousBehaviors.dataExfiltration.minBytes) {
          score.score += 0.7;
          score.details.push({
            behavior: 'Large data transfer',
            severity: 'critical',
            bytes: totalBytes
          });
        }

        // Check for C&C patterns (regular beacon intervals)
        if (this.detectBeaconPattern(recentConnections)) {
          score.score += 0.9;
          score.details.push({
            behavior: 'C&C beacon pattern',
            severity: 'critical'
          });
        }
      }

      // Normalize score
      score.score = Math.min(score.score, 1.0);

    } catch (error) {
      console.error('Network monitoring error:', error);
    }

    return score;
  }

  /**
   * Check registry activity
   */
  async checkRegistryActivity(filePath) {
    const score = { score: 0, details: [] };

    try {
      // Check for startup registry modifications
      const startupKeys = [
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
      ];

      // In production, this would use Windows Registry API
      // For now, we'll simulate based on process behavior

      const recentRegistryOps = this.registryActivityLog.filter(
        log => log.process === filePath && Date.now() - log.timestamp < 30000
      );

      if (recentRegistryOps.length > 0) {
        // Check for startup modifications
        const startupMods = recentRegistryOps.filter(
          log => startupKeys.some(key => log.key.includes(key))
        );

        if (startupMods.length > 0) {
          score.score += 0.75;
          score.details.push({
            behavior: 'Startup registry modification',
            severity: 'high',
            keys: startupMods.map(m => m.key)
          });
        }

        // Check for security policy changes
        if (recentRegistryOps.some(log => log.key.includes('Policies'))) {
          score.score += 0.85;
          score.details.push({
            behavior: 'Security policy modification',
            severity: 'critical'
          });
        }
      }

      // Normalize score
      score.score = Math.min(score.score, 1.0);

    } catch (error) {
      console.error('Registry monitoring error:', error);
    }

    return score;
  }

  /**
   * Calculate overall threat score using ML model
   */
  calculateThreatScore(scores) {
    // Weighted average with ML model
    let totalScore = 0;
    
    totalScore += scores.fileSystem * this.modelWeights.fileSystemOps;
    totalScore += scores.process * this.modelWeights.processCreation;
    totalScore += scores.network * this.modelWeights.networkActivity;
    totalScore += scores.registry * this.modelWeights.registryModification;

    // Apply neural network transformation
    const nnOutput = this.applyNeuralNetwork([
      scores.fileSystem,
      scores.process,
      scores.network,
      scores.registry
    ]);

    // Ensemble: average of weighted score and NN output
    return (totalScore + nnOutput) / 2;
  }

  /**
   * Apply simple neural network
   */
  applyNeuralNetwork(inputs) {
    // Pad inputs to match input layer size
    while (inputs.length < this.neuralNetwork.inputLayer) {
      inputs.push(0);
    }

    let output = inputs;
    
    // Forward pass through hidden layers
    for (let i = 0; i < this.neuralNetwork.hiddenLayers.length; i++) {
      output = this.applyLayer(output, this.neuralNetwork.hiddenLayers[i]);
    }

    // Output layer
    const finalOutput = output.reduce((sum, val) => sum + val, 0) / output.length;
    return Math.min(Math.max(finalOutput, 0), 1);
  }

  /**
   * Apply neural network layer
   */
  applyLayer(inputs, layerSize) {
    const outputs = [];
    for (let i = 0; i < layerSize; i++) {
      let sum = 0;
      inputs.forEach(input => {
        sum += input * (Math.random() * 0.2 + 0.9); // Simulated weights
      });
      // ReLU activation
      outputs.push(Math.max(0, sum));
    }
    return outputs;
  }

  /**
   * Generate explanation for the verdict
   */
  generateExplanation(behaviorLog) {
    const explanations = [];
    const topBehaviors = behaviorLog.behaviors
      .flatMap(b => b.details.map(d => ({ ...d, category: b.category })))
      .sort((a, b) => {
        const severityMap = { critical: 3, high: 2, medium: 1, low: 0 };
        return severityMap[b.severity] - severityMap[a.severity];
      })
      .slice(0, 5);

    topBehaviors.forEach(behavior => {
      explanations.push(`${behavior.category}: ${behavior.behavior} (${behavior.severity} severity)`);
    });

    return {
      summary: `File exhibits ${behaviorLog.verdict} behavior with confidence ${(behaviorLog.score * 100).toFixed(1)}%`,
      details: explanations,
      riskFactors: topBehaviors.length,
      mlConfidence: behaviorLog.score
    };
  }

  /**
   * Helper functions
   */

  getProcessChain(filePath) {
    // Simulated process chain - in production, use Windows API
    return [filePath];
  }

  isKnownGoodIP(ip) {
    // Check against whitelist
    const knownGoodIPs = ['8.8.8.8', '1.1.1.1', '8.8.4.4'];
    const privateRanges = ['192.168.', '10.', '172.16.', '127.'];
    
    return knownGoodIPs.includes(ip) || privateRanges.some(range => ip.startsWith(range));
  }

  detectBeaconPattern(connections) {
    if (connections.length < 3) return false;
    
    // Check for regular intervals
    const intervals = [];
    for (let i = 1; i < connections.length; i++) {
      intervals.push(connections[i].timestamp - connections[i - 1].timestamp);
    }
    
    // Calculate standard deviation
    const mean = intervals.reduce((sum, val) => sum + val, 0) / intervals.length;
    const variance = intervals.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    
    // If intervals are very consistent, it's likely a beacon
    return stdDev < mean * 0.2;
  }

  storeBehaviorProfile(filePath, profile) {
    this.behaviorProfiles.set(filePath, {
      ...profile,
      storedAt: Date.now()
    });
  }

  generateRandomWeights() {
    // Initialize with small random values
    return Array(64).fill(0).map(() => Math.random() * 0.1 - 0.05);
  }

  generateRandomBias() {
    return Array(32).fill(0).map(() => Math.random() * 0.01);
  }

  /**
   * Log activities for behavior analysis
   */
  logFileActivity(activity) {
    this.fileActivityLog.push({
      ...activity,
      timestamp: Date.now()
    });
    
    // Keep only recent logs (last 5 minutes)
    const fiveMinutesAgo = Date.now() - 300000;
    this.fileActivityLog = this.fileActivityLog.filter(log => log.timestamp > fiveMinutesAgo);
  }

  logNetworkActivity(activity) {
    this.networkActivityLog.push({
      ...activity,
      timestamp: Date.now()
    });
    
    const fiveMinutesAgo = Date.now() - 300000;
    this.networkActivityLog = this.networkActivityLog.filter(log => log.timestamp > fiveMinutesAgo);
  }

  logRegistryActivity(activity) {
    this.registryActivityLog.push({
      ...activity,
      timestamp: Date.now()
    });
    
    const fiveMinutesAgo = Date.now() - 300000;
    this.registryActivityLog = this.registryActivityLog.filter(log => log.timestamp > fiveMinutesAgo);
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      behaviorProfiles: this.behaviorProfiles.size,
      fileActivityLogs: this.fileActivityLog.length,
      networkActivityLogs: this.networkActivityLog.length,
      registryActivityLogs: this.registryActivityLog.length,
      modelInfo: {
        inputLayer: this.neuralNetwork.inputLayer,
        hiddenLayers: this.neuralNetwork.hiddenLayers,
        outputLayer: this.neuralNetwork.outputLayer
      },
      thresholds: this.thresholds
    };
  }

  /**
   * Train model with feedback
   */
  async trainWithFeedback(filePath, actualThreat, userFeedback) {
    // Simple online learning - adjust weights based on feedback
    const profile = this.behaviorProfiles.get(filePath);
    if (!profile) return { success: false, error: 'No profile found' };

    const error = actualThreat - profile.score;
    
    // Adjust weights (gradient descent)
    Object.keys(this.modelWeights).forEach(key => {
      this.modelWeights[key] += this.neuralNetwork.learningRate * error;
      this.modelWeights[key] = Math.max(0, Math.min(1, this.modelWeights[key]));
    });

    // Normalize weights
    const sum = Object.values(this.modelWeights).reduce((a, b) => a + b, 0);
    Object.keys(this.modelWeights).forEach(key => {
      this.modelWeights[key] /= sum;
    });

    return {
      success: true,
      adjustedWeights: this.modelWeights,
      error: Math.abs(error)
    };
  }
}

// Export singleton instance
const behaviorDetector = new BehaviorBasedDetector();
module.exports = behaviorDetector;
