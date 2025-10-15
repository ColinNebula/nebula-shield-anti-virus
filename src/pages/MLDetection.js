import React, { useState, useEffect, useCallback } from 'react';
import { 
  Activity, Brain, AlertTriangle, TrendingUp, Cpu, Network, 
  Database, Shield, Zap, BarChart3, CheckCircle, XCircle, 
  Clock, Download, Upload, RefreshCw, Play, Pause, Settings 
} from 'lucide-react';
import mlAnomalyDetector from '../services/mlAnomalyDetection';
import toast from 'react-hot-toast';
import './MLDetection.css';

/**
 * ML Detection Dashboard Component
 * Provides real-time monitoring, training, and visualization of ML anomaly detection
 */
const MLDetection = () => {
  const [stats, setStats] = useState(null);
  const [zeroDayThreats, setZeroDayThreats] = useState([]);
  const [recentDetections, setRecentDetections] = useState([]);
  const [modelStatus, setModelStatus] = useState({ network: false, process: false, behavior: false });
  const [isTraining, setIsTraining] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedTab, setSelectedTab] = useState('overview');
  const [baseline, setBaseline] = useState(null);

  // Load ML data
  const loadMLData = useCallback(async () => {
    try {
      // Get statistics
      const statistics = mlAnomalyDetector.getStatistics();
      setStats(statistics);
      setModelStatus(statistics.modelsStatus);

      // Get zero-day candidates
      const candidates = mlAnomalyDetector.getZeroDayCandidates();
      setZeroDayThreats(candidates);

      // Get recent detections (last 10)
      const history = mlAnomalyDetector.detectionHistory.slice(-10).reverse();
      setRecentDetections(history);

      // Get baseline profile
      setBaseline(mlAnomalyDetector.baseline);
    } catch (error) {
      console.error('Failed to load ML data:', error);
      toast('Failed to load ML detection data', { icon: '❌' });
    }
  }, []);

  useEffect(() => {
    loadMLData();

    if (autoRefresh) {
      const interval = setInterval(loadMLData, 5000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh, loadMLData]);

  // Train models with demo data
  const handleTrainModels = async () => {
    setIsTraining(true);
    toast.loading('🧠 Training ML models...', { duration: 2000 });

    try {
      // Generate synthetic training data
      const trainingData = generateSyntheticTrainingData(500);
      
      const results = await mlAnomalyDetector.trainModels(trainingData);
      
      toast.success(
        `✅ Models trained successfully! Network: ${results.network.samples} samples, ` +
        `Process: ${results.process.samples} samples, Behavior: ${results.behavior.samples} samples`,
        { duration: 5000 }
      );
      
      await loadMLData();
    } catch (error) {
      console.error('Training error:', error);
      toast.error('Failed to train models: ' + error.message);
    } finally {
      setIsTraining(false);
    }
  };

  // Export trained models
  const handleExportModels = () => {
    try {
      const modelData = mlAnomalyDetector.exportModels();
      const blob = new Blob([JSON.stringify(modelData, null, 2)], { 
        type: 'application/json' 
      });
      
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ml-models-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      toast.success('✅ ML models exported successfully');
    } catch (error) {
      toast.error('Failed to export models: ' + error.message);
    }
  };

  // Import trained models
  const handleImportModels = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const modelData = JSON.parse(e.target.result);
        mlAnomalyDetector.importModels(modelData);
        
        toast.success('✅ ML models imported successfully');
        await loadMLData();
      } catch (error) {
        toast.error('Failed to import models: ' + error.message);
      }
    };
    reader.readAsText(file);
  };

  // Simulate anomaly detection
  const handleTestDetection = async () => {
    toast.loading('🔍 Running test detection...', { duration: 2000 });

    try {
      // Test network anomaly
      const testPacket = {
        type: 'network',
        sourceIP: '192.168.1.100',
        destinationIP: '10.0.0.1',
        port: 4444, // High-risk port
        protocol: 'TCP',
        size: 8000, // Unusually large
        payload: generateRandomPayload(),
        headers: {},
        timestamp: Date.now(),
        country: 'Unknown'
      };

      const result = await mlAnomalyDetector.detectNetworkAnomaly(testPacket);
      
      if (result.anomaly) {
        toast(
          `⚠️ Anomaly Detected! Score: ${(result.score * 100).toFixed(1)}%, ` +
          `Confidence: ${(result.confidence * 100).toFixed(1)}%`,
          { icon: '⚠️', duration: 5000 }
        );
      } else {
        toast.success('✅ Normal behavior - no anomaly detected');
      }
      
      await loadMLData();
    } catch (error) {
      toast.error('Test detection failed: ' + error.message);
    }
  };

  if (!stats) {
    return (
      <div className="ml-detection-loading">
        <div className="spinner"></div>
        <p>Loading ML Detection System...</p>
      </div>
    );
  }

  return (
    <div className="ml-detection-page">
      {/* Header */}
      <div className="ml-header">
        <div className="ml-header-content">
          <Brain size={32} className="ml-header-icon" />
          <div>
            <h1>Machine Learning Detection</h1>
            <p>AI-powered zero-day threat detection and behavioral analysis</p>
          </div>
        </div>
        
        <div className="ml-header-actions">
          <button 
            className="btn-secondary"
            onClick={() => setAutoRefresh(!autoRefresh)}
            title={autoRefresh ? 'Pause auto-refresh' : 'Resume auto-refresh'}
          >
            {autoRefresh ? <Pause size={16} /> : <Play size={16} />}
            {autoRefresh ? 'Pause' : 'Resume'}
          </button>
          
          <button 
            className="btn-secondary"
            onClick={loadMLData}
            disabled={autoRefresh}
            title="Refresh data"
          >
            <RefreshCw size={16} />
            Refresh
          </button>
          
          <button 
            className="btn-primary"
            onClick={handleTrainModels}
            disabled={isTraining}
            title="Train ML models with data"
          >
            <Zap size={16} />
            {isTraining ? 'Training...' : 'Train Models'}
          </button>
        </div>
      </div>

      {/* Statistics Overview */}
      <div className="ml-stats-grid">
        <div className="ml-stat-card">
          <div className="ml-stat-icon" style={{ backgroundColor: '#3b82f6' }}>
            <Activity size={24} />
          </div>
          <div className="ml-stat-content">
            <p className="ml-stat-label">Total Detections</p>
            <p className="ml-stat-value">{stats.totalDetections.toLocaleString()}</p>
            <p className="ml-stat-trend">All-time analysis count</p>
          </div>
        </div>

        <div className="ml-stat-card">
          <div className="ml-stat-icon" style={{ backgroundColor: '#ef4444' }}>
            <AlertTriangle size={24} />
          </div>
          <div className="ml-stat-content">
            <p className="ml-stat-label">Anomalies Found</p>
            <p className="ml-stat-value">{stats.anomalyCount.toLocaleString()}</p>
            <p className="ml-stat-trend">{stats.anomalyRate}% detection rate</p>
          </div>
        </div>

        <div className="ml-stat-card">
          <div className="ml-stat-icon" style={{ backgroundColor: '#f59e0b' }}>
            <Shield size={24} />
          </div>
          <div className="ml-stat-content">
            <p className="ml-stat-label">Zero-Day Candidates</p>
            <p className="ml-stat-value">{stats.zeroDayCount}</p>
            <p className="ml-stat-trend">Potential unknown threats</p>
          </div>
        </div>

        <div className="ml-stat-card">
          <div className="ml-stat-icon" style={{ backgroundColor: '#10b981' }}>
            <TrendingUp size={24} />
          </div>
          <div className="ml-stat-content">
            <p className="ml-stat-label">Avg Confidence</p>
            <p className="ml-stat-value">{(parseFloat(stats.avgConfidence) * 100).toFixed(1)}%</p>
            <p className="ml-stat-trend">Prediction accuracy</p>
          </div>
        </div>
      </div>

      {/* Model Status Cards */}
      <div className="ml-models-section">
        <h2 className="section-title">
          <Cpu size={20} />
          Detection Models Status
        </h2>
        
        <div className="ml-models-grid">
          <ModelCard
            name="Network Model"
            type="network"
            trained={modelStatus.network}
            icon={<Network size={32} />}
            color="#3b82f6"
            description="Analyzes network traffic patterns for suspicious behavior"
          />
          
          <ModelCard
            name="Process Model"
            type="process"
            trained={modelStatus.process}
            icon={<Cpu size={32} />}
            color="#8b5cf6"
            description="Monitors process behavior and resource usage anomalies"
          />
          
          <ModelCard
            name="Behavior Model"
            type="behavior"
            trained={modelStatus.behavior}
            icon={<Activity size={32} />}
            color="#ec4899"
            description="Detects unusual behavioral patterns and event sequences"
          />
        </div>
      </div>

      {/* Tabs */}
      <div className="ml-tabs">
        <button 
          className={`ml-tab ${selectedTab === 'overview' ? 'active' : ''}`}
          onClick={() => setSelectedTab('overview')}
        >
          <BarChart3 size={16} />
          Overview
        </button>
        
        <button 
          className={`ml-tab ${selectedTab === 'zero-day' ? 'active' : ''}`}
          onClick={() => setSelectedTab('zero-day')}
        >
          <AlertTriangle size={16} />
          Zero-Day Threats
          {stats.zeroDayCount > 0 && (
            <span className="ml-tab-badge">{stats.zeroDayCount}</span>
          )}
        </button>
        
        <button 
          className={`ml-tab ${selectedTab === 'detections' ? 'active' : ''}`}
          onClick={() => setSelectedTab('detections')}
        >
          <Activity size={16} />
          Recent Detections
        </button>
        
        <button 
          className={`ml-tab ${selectedTab === 'baseline' ? 'active' : ''}`}
          onClick={() => setSelectedTab('baseline')}
        >
          <Database size={16} />
          Baseline Profile
        </button>
        
        <button 
          className={`ml-tab ${selectedTab === 'settings' ? 'active' : ''}`}
          onClick={() => setSelectedTab('settings')}
        >
          <Settings size={16} />
          Settings
        </button>
      </div>

      {/* Tab Content */}
      <div className="ml-tab-content">
        {selectedTab === 'overview' && (
          <OverviewTab 
            stats={stats} 
            recentDetections={recentDetections.slice(0, 5)}
            onTestDetection={handleTestDetection}
          />
        )}
        
        {selectedTab === 'zero-day' && (
          <ZeroDayTab threats={zeroDayThreats} />
        )}
        
        {selectedTab === 'detections' && (
          <DetectionsTab detections={recentDetections} />
        )}
        
        {selectedTab === 'baseline' && (
          <BaselineTab baseline={baseline} />
        )}
        
        {selectedTab === 'settings' && (
          <SettingsTab 
            onExport={handleExportModels}
            onImport={handleImportModels}
            onTrain={handleTrainModels}
            isTraining={isTraining}
          />
        )}
      </div>
    </div>
  );
};

// ==================== SUB-COMPONENTS ====================

/**
 * Model Status Card
 */
const ModelCard = ({ name, type, trained, icon, color, description }) => (
  <div className="ml-model-card">
    <div className="ml-model-icon" style={{ backgroundColor: color }}>
      {icon}
    </div>
    <div className="ml-model-content">
      <h3>{name}</h3>
      <p className="ml-model-description">{description}</p>
      <div className="ml-model-status">
        {trained ? (
          <>
            <CheckCircle size={16} style={{ color: '#10b981' }} />
            <span style={{ color: '#10b981' }}>Trained</span>
          </>
        ) : (
          <>
            <XCircle size={16} style={{ color: '#ef4444' }} />
            <span style={{ color: '#ef4444' }}>Untrained</span>
          </>
        )}
      </div>
    </div>
  </div>
);

/**
 * Overview Tab
 */
const OverviewTab = ({ stats, recentDetections, onTestDetection }) => (
  <div className="overview-tab">
    <div className="overview-grid">
      <div className="overview-card">
        <h3>Detection Performance</h3>
        <div className="performance-stats">
          <div className="perf-stat">
            <label>Anomaly Rate</label>
            <div className="perf-bar">
              <div 
                className="perf-bar-fill" 
                style={{ width: `${stats.anomalyRate}%`, backgroundColor: '#ef4444' }}
              />
            </div>
            <span>{stats.anomalyRate}%</span>
          </div>
          
          <div className="perf-stat">
            <label>Avg Detection Score</label>
            <div className="perf-bar">
              <div 
                className="perf-bar-fill" 
                style={{ width: `${parseFloat(stats.avgScore) * 100}%`, backgroundColor: '#f59e0b' }}
              />
            </div>
            <span>{(parseFloat(stats.avgScore) * 100).toFixed(1)}%</span>
          </div>
          
          <div className="perf-stat">
            <label>Avg Confidence</label>
            <div className="perf-bar">
              <div 
                className="perf-bar-fill" 
                style={{ width: `${parseFloat(stats.avgConfidence) * 100}%`, backgroundColor: '#10b981' }}
              />
            </div>
            <span>{(parseFloat(stats.avgConfidence) * 100).toFixed(1)}%</span>
          </div>
        </div>
      </div>

      <div className="overview-card">
        <h3>Quick Actions</h3>
        <div className="quick-actions">
          <button className="action-btn" onClick={onTestDetection}>
            <Zap size={20} />
            <div>
              <strong>Run Test Detection</strong>
              <p>Simulate anomaly with sample data</p>
            </div>
          </button>
        </div>
      </div>
    </div>

    {recentDetections.length > 0 && (
      <div className="overview-card full-width">
        <h3>Latest Detections</h3>
        <div className="detections-list">
          {recentDetections.map((detection, index) => (
            <div key={index} className="detection-item-mini">
              <div className={`detection-indicator ${detection.prediction.anomaly ? 'anomaly' : 'normal'}`} />
              <div className="detection-info">
                <strong>{detection.type.toUpperCase()}</strong>
                <span className="detection-time">
                  <Clock size={12} />
                  {new Date(detection.timestamp).toLocaleTimeString()}
                </span>
              </div>
              <div className="detection-score">
                Score: {(detection.score * 100).toFixed(1)}%
              </div>
            </div>
          ))}
        </div>
      </div>
    )}
  </div>
);

/**
 * Zero-Day Threats Tab
 */
const ZeroDayTab = ({ threats }) => (
  <div className="zero-day-tab">
    {threats.length === 0 ? (
      <div className="empty-state">
        <Shield size={64} style={{ color: '#10b981' }} />
        <h3>No Zero-Day Threats Detected</h3>
        <p>The system has not identified any potential zero-day exploits.</p>
      </div>
    ) : (
      <div className="threats-list">
        {threats.map((threat, index) => (
          <div key={index} className="threat-card">
            <div className="threat-header">
              <AlertTriangle size={24} style={{ color: '#ef4444' }} />
              <div>
                <h3>Zero-Day Candidate #{index + 1}</h3>
                <p className="threat-time">
                  {new Date(threat.timestamp).toLocaleString()}
                </p>
              </div>
              <div className="threat-score">
                <span className="score-label">Risk Score</span>
                <span className="score-value critical">
                  {(threat.zeroDayScore * 100).toFixed(1)}%
                </span>
              </div>
            </div>
            
            <div className="threat-details">
              <div className="detail-row">
                <label>Ensemble Score:</label>
                <span>{(threat.ensembleScore * 100).toFixed(1)}%</span>
              </div>
              
              <div className="detail-row">
                <label>Models Triggered:</label>
                <span>{threat.results.length} / 3</span>
              </div>
              
              {threat.results.map((result, i) => (
                <div key={i} className="model-result">
                  <strong>{result.type.toUpperCase()} Model:</strong>
                  <span className={result.anomaly ? 'text-danger' : 'text-success'}>
                    {result.anomaly ? '⚠️ ANOMALY' : '✅ Normal'}
                  </span>
                  <span>Score: {(result.score * 100).toFixed(1)}%</span>
                  <span>Confidence: {(result.confidence * 100).toFixed(1)}%</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    )}
  </div>
);

/**
 * Recent Detections Tab
 */
const DetectionsTab = ({ detections }) => (
  <div className="detections-tab">
    {detections.length === 0 ? (
      <div className="empty-state">
        <Activity size={64} style={{ color: '#6b7280' }} />
        <h3>No Recent Detections</h3>
        <p>No anomaly detection activity to display.</p>
      </div>
    ) : (
      <div className="detections-table">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Type</th>
              <th>Status</th>
              <th>Score</th>
              <th>Confidence</th>
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody>
            {detections.map((detection, index) => (
              <tr key={index}>
                <td>{new Date(detection.timestamp).toLocaleString()}</td>
                <td>
                  <span className={`type-badge type-${detection.type}`}>
                    {detection.type.toUpperCase()}
                  </span>
                </td>
                <td>
                  {detection.prediction.anomaly ? (
                    <span className="status-badge status-anomaly">
                      <AlertTriangle size={14} />
                      Anomaly
                    </span>
                  ) : (
                    <span className="status-badge status-normal">
                      <CheckCircle size={14} />
                      Normal
                    </span>
                  )}
                </td>
                <td>
                  <div className="score-bar">
                    <div 
                      className="score-bar-fill"
                      style={{ 
                        width: `${detection.score * 100}%`,
                        backgroundColor: detection.score > 0.7 ? '#ef4444' : 
                                       detection.score > 0.5 ? '#f59e0b' : '#10b981'
                      }}
                    />
                    <span>{(detection.score * 100).toFixed(1)}%</span>
                  </div>
                </td>
                <td>{(detection.confidence * 100).toFixed(1)}%</td>
                <td>
                  <span className={`action-badge action-${detection.prediction.recommendation.severity}`}>
                    {detection.prediction.recommendation.action.replace(/_/g, ' ')}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </div>
);

/**
 * Baseline Profile Tab
 */
const BaselineTab = ({ baseline }) => {
  if (!baseline) return null;

  return (
    <div className="baseline-tab">
      <div className="baseline-grid">
        <div className="baseline-card">
          <h3>
            <Network size={20} />
            Network Baseline
          </h3>
          <div className="baseline-stats">
            <div className="baseline-stat">
              <label>Avg Packet Size</label>
              <span>{baseline.networkBaseline.avgPacketSize} bytes</span>
            </div>
            <div className="baseline-stat">
              <label>Avg Request Rate</label>
              <span>{baseline.networkBaseline.avgRequestRate} req/min</span>
            </div>
            <div className="baseline-stat">
              <label>Normal Ports</label>
              <span>{baseline.networkBaseline.normalPorts.join(', ')}</span>
            </div>
            <div className="baseline-stat">
              <label>Normal Protocols</label>
              <span>{baseline.networkBaseline.normalProtocols.join(', ')}</span>
            </div>
          </div>
        </div>

        <div className="baseline-card">
          <h3>
            <Cpu size={20} />
            Process Baseline
          </h3>
          <div className="baseline-stats">
            <div className="baseline-stat">
              <label>Normal CPU Usage</label>
              <span>{baseline.processBaseline.normalCPUUsage}%</span>
            </div>
            <div className="baseline-stat">
              <label>Normal Memory Usage</label>
              <span>{baseline.processBaseline.normalMemoryUsage}%</span>
            </div>
            <div className="baseline-stat">
              <label>File Access Rate</label>
              <span>{baseline.processBaseline.normalFileAccess}/min</span>
            </div>
            <div className="baseline-stat">
              <label>Network Calls</label>
              <span>{baseline.processBaseline.normalNetworkCalls}/min</span>
            </div>
          </div>
        </div>

        <div className="baseline-card">
          <h3>
            <Activity size={20} />
            Behavior Baseline
          </h3>
          <div className="baseline-stats">
            <div className="baseline-stat">
              <label>Avg Failed Logins</label>
              <span>{baseline.behaviorBaseline.avgFailedLogins}/hour</span>
            </div>
            <div className="baseline-stat">
              <label>API Calls</label>
              <span>{baseline.behaviorBaseline.avgAPICallsPerMinute}/min</span>
            </div>
            <div className="baseline-stat">
              <label>Registry Access</label>
              <span>{baseline.behaviorBaseline.normalRegistryAccess}/min</span>
            </div>
            <div className="baseline-stat">
              <label>DNS Queries</label>
              <span>{baseline.behaviorBaseline.normalDNSQueries}/min</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

/**
 * Settings Tab
 */
const SettingsTab = ({ onExport, onImport, onTrain, isTraining }) => (
  <div className="settings-tab">
    <div className="settings-section">
      <h3>Model Management</h3>
      <div className="settings-actions">
        <button className="btn-secondary" onClick={onTrain} disabled={isTraining}>
          <Zap size={16} />
          {isTraining ? 'Training...' : 'Train Models'}
        </button>
        
        <button className="btn-secondary" onClick={onExport}>
          <Download size={16} />
          Export Models
        </button>
        
        <label className="btn-secondary">
          <Upload size={16} />
          Import Models
          <input 
            type="file" 
            accept=".json" 
            onChange={onImport}
            style={{ display: 'none' }}
          />
        </label>
      </div>
      <p className="settings-description">
        Train, export, or import ML models. Training requires historical data for accurate predictions.
      </p>
    </div>

    <div className="settings-section">
      <h3>Detection Configuration</h3>
      <div className="settings-options">
        <div className="setting-option">
          <label>
            <input type="checkbox" defaultChecked />
            <span>Auto-Learning</span>
          </label>
          <p>Automatically update baseline with validated normal behavior</p>
        </div>
        
        <div className="setting-option">
          <label>
            <input type="checkbox" defaultChecked />
            <span>Zero-Day Detection</span>
          </label>
          <p>Enable advanced detection of potential zero-day exploits</p>
        </div>
        
        <div className="setting-option">
          <label>
            <input type="checkbox" defaultChecked />
            <span>Ensemble Voting</span>
          </label>
          <p>Use multiple models for more accurate predictions</p>
        </div>
      </div>
    </div>

    <div className="settings-section">
      <h3>Performance Thresholds</h3>
      <div className="settings-sliders">
        <div className="setting-slider">
          <label>Anomaly Threshold: 75%</label>
          <input type="range" min="50" max="95" defaultValue="75" />
          <p>Minimum score required to classify as anomaly</p>
        </div>
        
        <div className="setting-slider">
          <label>Confidence Threshold (High): 85%</label>
          <input type="range" min="70" max="99" defaultValue="85" />
          <p>Threshold for high-confidence alerts</p>
        </div>
      </div>
    </div>
  </div>
);

// ==================== HELPER FUNCTIONS ====================

/**
 * Generate synthetic training data for ML models
 */
function generateSyntheticTrainingData(count) {
  const data = [];
  
  for (let i = 0; i < count; i++) {
    const type = ['network', 'process', 'behavior'][Math.floor(Math.random() * 3)];
    
    if (type === 'network') {
      data.push({
        type: 'network',
        sourceIP: `192.168.1.${Math.floor(Math.random() * 255)}`,
        destinationIP: `10.0.0.${Math.floor(Math.random() * 255)}`,
        port: [80, 443, 22, 3389, 8080][Math.floor(Math.random() * 5)],
        protocol: ['HTTP', 'HTTPS', 'SSH', 'RDP'][Math.floor(Math.random() * 4)],
        size: 512 + Math.random() * 1000,
        payload: generateRandomPayload(),
        headers: {},
        timestamp: Date.now() - Math.random() * 86400000,
        country: 'US'
      });
    } else if (type === 'process') {
      data.push({
        type: 'process',
        name: ['chrome.exe', 'firefox.exe', 'explorer.exe'][Math.floor(Math.random() * 3)],
        cpuUsage: 10 + Math.random() * 30,
        memoryUsage: 20 + Math.random() * 40,
        fileAccess: Math.floor(Math.random() * 20),
        networkCalls: Math.floor(Math.random() * 10),
        parentProcess: 'explorer.exe',
        commandLine: '',
        registryAccess: Math.floor(Math.random() * 5),
        timestamp: Date.now() - Math.random() * 86400000
      });
    } else {
      data.push({
        type: 'behavior',
        eventType: ['login', 'api_call', 'file_creation'][Math.floor(Math.random() * 3)],
        user: 'user1',
        timestamp: Date.now() - Math.random() * 86400000,
        context: {},
        dataFlow: 'normal'
      });
    }
  }
  
  return data;
}

/**
 * Generate random payload for testing
 */
function generateRandomPayload() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({ length: 100 }, () => 
    chars.charAt(Math.floor(Math.random() * chars.length))
  ).join('');
}

export default MLDetection;
