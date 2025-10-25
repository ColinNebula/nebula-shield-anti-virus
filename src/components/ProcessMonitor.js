/**
 * Nebula Shield - Process Monitor Component
 * 
 * Real-time process monitoring dashboard with behavioral analysis
 */

import React, { useState, useEffect } from 'react';
import behavioralEngine from '../services/behavioralEngine';
import './ProcessMonitor.css';

const ProcessMonitor = () => {
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [stats, setStats] = useState(null);
  const [processes, setProcesses] = useState([]);
  const [suspiciousProcesses, setSuspiciousProcesses] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [selectedProcess, setSelectedProcess] = useState(null);
  const [processTree, setProcessTree] = useState([]);
  const [filter, setFilter] = useState('all'); // all, suspicious, running
  const [sortBy, setSortBy] = useState('suspicion'); // suspicion, cpu, memory, name

  useEffect(() => {
    // Load initial status
    loadStatus();

    // Set up event listeners
    behavioralEngine.on('monitoringStarted', handleMonitoringStarted);
    behavioralEngine.on('monitoringStopped', handleMonitoringStopped);
    behavioralEngine.on('scanComplete', handleScanComplete);
    behavioralEngine.on('suspiciousProcess', handleSuspiciousProcess);
    behavioralEngine.on('processBlocked', handleProcessBlocked);

    return () => {
      behavioralEngine.removeListener('monitoringStarted', handleMonitoringStarted);
      behavioralEngine.removeListener('monitoringStopped', handleMonitoringStopped);
      behavioralEngine.removeListener('scanComplete', handleScanComplete);
      behavioralEngine.removeListener('suspiciousProcess', handleSuspiciousProcess);
      behavioralEngine.removeListener('processBlocked', handleProcessBlocked);
    };
  }, []);

  const loadStatus = () => {
    const status = behavioralEngine.getStatus();
    setIsMonitoring(status.state.isMonitoring);
    setStats(status.stats);
    setSuspiciousProcesses(behavioralEngine.getSuspiciousProcesses());
    setAlerts(behavioralEngine.getAlerts().filter(a => !a.resolved));
    
    // Get all processes
    const allProcesses = Array.from(behavioralEngine.state.processCache.values());
    setProcesses(allProcesses);
  };

  const handleMonitoringStarted = () => {
    setIsMonitoring(true);
    loadStatus();
  };

  const handleMonitoringStopped = () => {
    setIsMonitoring(false);
  };

  const handleScanComplete = (data) => {
    loadStatus();
  };

  const handleSuspiciousProcess = (alert) => {
    setAlerts(prev => [alert, ...prev]);
    loadStatus();
  };

  const handleProcessBlocked = (data) => {
    loadStatus();
  };

  const toggleMonitoring = async () => {
    if (isMonitoring) {
      behavioralEngine.stopMonitoring();
    } else {
      await behavioralEngine.startMonitoring();
    }
  };

  const handleProcessClick = (process) => {
    setSelectedProcess(process);
    const tree = behavioralEngine.getProcessTree(process.pid);
    setProcessTree(tree);
  };

  const handleBlockProcess = async (process) => {
    await behavioralEngine.blockProcess(process);
    loadStatus();
  };

  const handleClearAlert = (alertId) => {
    behavioralEngine.clearAlert(alertId);
    setAlerts(behavioralEngine.getAlerts().filter(a => !a.resolved));
  };

  const handleExportData = () => {
    const data = behavioralEngine.exportData();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `behavioral-analysis-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getFilteredProcesses = () => {
    let filtered = processes;

    // Apply filter
    switch (filter) {
      case 'suspicious':
        filtered = suspiciousProcesses;
        break;
      case 'running':
        filtered = processes.filter(p => !p.whitelisted);
        break;
      default:
        filtered = processes;
    }

    // Apply sort
    return filtered.sort((a, b) => {
      switch (sortBy) {
        case 'suspicion':
          return (b.suspicionScore || 0) - (a.suspicionScore || 0);
        case 'cpu':
          return (b.cpu || 0) - (a.cpu || 0);
        case 'memory':
          return (b.memory || 0) - (a.memory || 0);
        case 'name':
          return (a.name || '').localeCompare(b.name || '');
        default:
          return 0;
      }
    });
  };

  const getSeverityColor = (score) => {
    if (score >= 90) return 'critical';
    if (score >= 80) return 'high';
    if (score >= 70) return 'medium';
    return 'low';
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatUptime = (ms) => {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  const filteredProcesses = getFilteredProcesses();

  return (
    <div className="process-monitor">
      <div className="monitor-header">
        <div className="header-title">
          <h2>🔍 Process Monitor</h2>
          <p>Real-time behavioral analysis and threat detection</p>
        </div>
        <div className="header-controls">
          <button 
            className={`monitor-toggle ${isMonitoring ? 'active' : ''}`}
            onClick={toggleMonitoring}
          >
            {isMonitoring ? '⏸ Stop Monitoring' : '▶ Start Monitoring'}
          </button>
          <button className="export-btn" onClick={handleExportData}>
            📊 Export Data
          </button>
        </div>
      </div>

      {/* Statistics Dashboard */}
      <div className="stats-dashboard">
        <div className="stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-info">
            <div className="stat-value">{stats?.currentProcesses || 0}</div>
            <div className="stat-label">Processes Monitored</div>
          </div>
        </div>

        <div className="stat-card suspicious">
          <div className="stat-icon">⚠️</div>
          <div className="stat-info">
            <div className="stat-value">{stats?.suspiciousProcesses || 0}</div>
            <div className="stat-label">Suspicious Detected</div>
          </div>
        </div>

        <div className="stat-card blocked">
          <div className="stat-icon">🛡️</div>
          <div className="stat-info">
            <div className="stat-value">{stats?.blockedProcesses || 0}</div>
            <div className="stat-label">Threats Blocked</div>
          </div>
        </div>

        <div className="stat-card alerts">
          <div className="stat-icon">🚨</div>
          <div className="stat-info">
            <div className="stat-value">{stats?.activeAlerts || 0}</div>
            <div className="stat-label">Active Alerts</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">📈</div>
          <div className="stat-info">
            <div className="stat-value">{stats?.totalProcessesScanned || 0}</div>
            <div className="stat-label">Total Scanned</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">⏱️</div>
          <div className="stat-info">
            <div className="stat-value">{stats ? formatUptime(stats.uptime) : '0s'}</div>
            <div className="stat-label">Uptime</div>
          </div>
        </div>
      </div>

      {/* Active Alerts */}
      {alerts.length > 0 && (
        <div className="alerts-section">
          <h3>🚨 Active Alerts</h3>
          <div className="alerts-list">
            {alerts.slice(0, 5).map(alert => (
              <div key={alert.id} className={`alert-item severity-${alert.severity}`}>
                <div className="alert-icon">⚠️</div>
                <div className="alert-content">
                  <div className="alert-title">
                    Suspicious Process: {alert.process.name} (PID: {alert.process.pid})
                  </div>
                  <div className="alert-details">
                    Score: {alert.process.suspicionScore} | 
                    Path: {alert.process.path} | 
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </div>
                  <div className="alert-flags">
                    {alert.process.flags.slice(0, 3).map((flag, idx) => (
                      <span key={idx} className="flag-badge">{flag}</span>
                    ))}
                  </div>
                </div>
                <button 
                  className="clear-alert-btn"
                  onClick={() => handleClearAlert(alert.id)}
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Process List Controls */}
      <div className="process-controls">
        <div className="filter-group">
          <label>Filter:</label>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="all">All Processes</option>
            <option value="suspicious">Suspicious Only</option>
            <option value="running">Running (No System)</option>
          </select>
        </div>

        <div className="sort-group">
          <label>Sort by:</label>
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
            <option value="suspicion">Suspicion Score</option>
            <option value="cpu">CPU Usage</option>
            <option value="memory">Memory Usage</option>
            <option value="name">Name</option>
          </select>
        </div>

        <div className="process-count">
          Showing {filteredProcesses.length} processes
        </div>
      </div>

      {/* Process List */}
      <div className="process-list-container">
        <table className="process-table">
          <thead>
            <tr>
              <th>PID</th>
              <th>Name</th>
              <th>Path</th>
              <th>CPU</th>
              <th>Memory</th>
              <th>Suspicion</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredProcesses.map(process => (
              <tr 
                key={process.pid}
                className={`process-row ${selectedProcess?.pid === process.pid ? 'selected' : ''}`}
                onClick={() => handleProcessClick(process)}
              >
                <td>{process.pid}</td>
                <td className="process-name">
                  {process.whitelisted && <span className="whitelist-badge">✓</span>}
                  {process.name}
                </td>
                <td className="process-path" title={process.path}>{process.path}</td>
                <td>{process.cpu?.toFixed(1)}%</td>
                <td>{formatBytes(process.memory)}</td>
                <td>
                  <div className={`suspicion-score severity-${getSeverityColor(process.suspicionScore)}`}>
                    {process.suspicionScore || 0}
                  </div>
                </td>
                <td>
                  {process.whitelisted ? (
                    <span className="status-badge trusted">Trusted</span>
                  ) : process.suspicionScore >= 70 ? (
                    <span className="status-badge suspicious">Suspicious</span>
                  ) : (
                    <span className="status-badge clean">Clean</span>
                  )}
                </td>
                <td>
                  {!process.whitelisted && process.suspicionScore >= 70 && (
                    <button 
                      className="block-btn"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleBlockProcess(process);
                      }}
                    >
                      🛡️ Block
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Process Details Panel */}
      {selectedProcess && (
        <div className="process-details">
          <div className="details-header">
            <h3>Process Details: {selectedProcess.name}</h3>
            <button onClick={() => setSelectedProcess(null)}>✕</button>
          </div>

          <div className="details-content">
            <div className="detail-section">
              <h4>Basic Information</h4>
              <div className="detail-grid">
                <div className="detail-item">
                  <label>PID:</label>
                  <span>{selectedProcess.pid}</span>
                </div>
                <div className="detail-item">
                  <label>Name:</label>
                  <span>{selectedProcess.name}</span>
                </div>
                <div className="detail-item">
                  <label>Path:</label>
                  <span>{selectedProcess.path}</span>
                </div>
                <div className="detail-item">
                  <label>Parent PID:</label>
                  <span>{selectedProcess.parent}</span>
                </div>
                <div className="detail-item">
                  <label>User:</label>
                  <span>{selectedProcess.user}</span>
                </div>
                <div className="detail-item">
                  <label>Suspicion Score:</label>
                  <span className={`suspicion-score severity-${getSeverityColor(selectedProcess.suspicionScore)}`}>
                    {selectedProcess.suspicionScore}
                  </span>
                </div>
              </div>
            </div>

            {selectedProcess.flags && selectedProcess.flags.length > 0 && (
              <div className="detail-section">
                <h4>⚠️ Flags ({selectedProcess.flags.length})</h4>
                <div className="flags-list">
                  {selectedProcess.flags.map((flag, idx) => (
                    <div key={idx} className="flag-item">{flag}</div>
                  ))}
                </div>
              </div>
            )}

            {selectedProcess.behaviors && selectedProcess.behaviors.length > 0 && (
              <div className="detail-section">
                <h4>🎯 Detected Behaviors</h4>
                <div className="behaviors-list">
                  {selectedProcess.behaviors.map((behavior, idx) => (
                    <div key={idx} className="behavior-item">
                      <div className="behavior-type">{behavior.type}</div>
                      <div className="behavior-desc">{behavior.description}</div>
                      <div className="behavior-weight">Weight: {behavior.weight}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {processTree.length > 0 && (
              <div className="detail-section">
                <h4>🌳 Process Tree</h4>
                <div className="process-tree">
                  {processTree.map((proc, idx) => (
                    <div 
                      key={idx} 
                      className="tree-item"
                      style={{ paddingLeft: `${proc.level * 20}px` }}
                    >
                      <span className="tree-icon">{proc.level > 0 ? '└─' : ''}</span>
                      <span className="tree-name">{proc.name}</span>
                      <span className="tree-pid">(PID: {proc.pid})</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default ProcessMonitor;
