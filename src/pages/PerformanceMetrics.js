/**
 * Performance Metrics Dashboard
 * Displays real-time and historical performance metrics
 */

import React, { useState, useEffect, useRef } from 'react';
import { 
  Activity, Cpu, HardDrive, Zap, TrendingUp, TrendingDown,
  AlertTriangle, CheckCircle, Clock, BarChart3, Database,
  Wifi, RefreshCw, Monitor, Thermometer, ArrowUpDown,
  List, X
} from 'lucide-react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import './PerformanceMetrics.css';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

// In development with React dev server, use proxy (relative URLs)
// In Electron or production, use direct backend URLs
const isElectron = typeof window !== 'undefined' && window.electronAPI?.isElectron;
const API_BASE_URL = isElectron ? 'http://localhost:8080' : '';

const PerformanceMetrics = () => {
  const [metrics, setMetrics] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('24h');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [historicalData, setHistoricalData] = useState({
    cpu: [],
    memory: [],
    disk: [],
    timestamps: []
  });
  const [processes, setProcesses] = useState([]);
  const [showProcesses, setShowProcesses] = useState(false);
  const maxDataPoints = 60; // Keep last 60 data points (5 minutes at 5s interval)

  useEffect(() => {
    loadMetrics();
    loadDashboard();

    if (autoRefresh) {
      const interval = setInterval(() => {
        loadMetrics();
        loadDashboard();
      }, 5000); // Refresh every 5 seconds

      return () => clearInterval(interval);
    }
  }, [autoRefresh, timeRange]);

  const loadMetrics = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/system/health`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const data = await response.json();
      // Validate the response structure
      if (data && data.health && data.cpu && data.memory && data.disk) {
        setMetrics(data);
        
        // Update historical data
        const now = new Date().toLocaleTimeString();
        setHistoricalData(prev => {
          const newData = {
            cpu: [...prev.cpu, data.cpu.usage].slice(-maxDataPoints),
            memory: [...prev.memory, data.memory.usagePercent].slice(-maxDataPoints),
            disk: [...prev.disk, data.disk.usagePercent].slice(-maxDataPoints),
            timestamps: [...prev.timestamps, now].slice(-maxDataPoints)
          };
          return newData;
        });
        
        // Update processes if available
        if (data.processes && data.processes.list) {
          setProcesses(data.processes.list);
        }
      } else {
        console.error('Invalid metrics data structure:', data);
        setMetrics(null);
      }
      setLoading(false);
    } catch (error) {
      console.error('Failed to load metrics:', error);
      setMetrics(null);
      setLoading(false);
    }
  };

  const loadDashboard = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/analytics/dashboard?timeRange=${timeRange}`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const data = await response.json();
      // Validate the response structure
      if (data && data.overview) {
        setDashboard(data);
      } else {
        console.error('Invalid dashboard data structure:', data);
        setDashboard(null);
      }
    } catch (error) {
      console.error('Failed to load dashboard:', error);
      // Set dashboard to null on error so UI can handle gracefully
      setDashboard(null);
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatUptime = (seconds) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  const getHealthColor = (status) => {
    switch (status) {
      case 'healthy': return '#10b981';
      case 'warning': return '#f59e0b';
      case 'critical': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const getHealthIcon = (status) => {
    switch (status) {
      case 'healthy': return <CheckCircle size={24} color="#10b981" />;
      case 'warning': return <AlertTriangle size={24} color="#f59e0b" />;
      case 'critical': return <AlertTriangle size={24} color="#ef4444" />;
      default: return <Activity size={24} color="#6b7280" />;
    }
  };

  if (loading) {
    return (
      <div className="performance-loading">
        <RefreshCw className="spinner" size={48} />
        <p>Loading performance metrics...</p>
      </div>
    );
  }

  if (!metrics) {
    return (
      <div className="performance-error">
        <AlertTriangle size={48} color="#ef4444" />
        <h2>Unable to Load Metrics</h2>
        <p>Failed to connect to the backend server. Please ensure the server is running.</p>
        <button onClick={loadMetrics} className="retry-button">
          <RefreshCw size={20} />
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="performance-container">
      <div className="performance-header">
        <div className="header-left">
          <Activity size={32} />
          <h1>Performance Metrics</h1>
        </div>
        <div className="header-right">
          <select 
            value={timeRange} 
            onChange={(e) => setTimeRange(e.target.value)}
            className="time-range-select"
          >
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          <button 
            className={`refresh-toggle ${autoRefresh ? 'active' : ''}`}
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            <RefreshCw size={20} className={autoRefresh ? 'spinning' : ''} />
            Auto Refresh
          </button>
        </div>
      </div>

      {/* System Health Overview */}
      {metrics && metrics.health && typeof metrics.health.score !== 'undefined' && (
        <div className="health-overview">
          <div className="health-score">
            <div 
              className="health-circle" 
              style={{ 
                background: `conic-gradient(${getHealthColor(metrics.health.status)} ${metrics.health.score}%, #2d3748 ${metrics.health.score}%)`
              }}
            >
              <div className="health-inner">
                <div className="health-value">{metrics.health.score}</div>
                <div className="health-label">Health Score</div>
              </div>
            </div>
            <div className="health-status">
              {getHealthIcon(metrics.health.status)}
              <span>{metrics.health.status.toUpperCase()}</span>
              <p>{metrics.health.message}</p>
            </div>
          </div>

          <div className="health-alerts">
            <h3><AlertTriangle size={20} /> Active Alerts</h3>
            {metrics.alerts && Array.isArray(metrics.alerts) && metrics.alerts.length > 0 ? (
              <div className="alerts-list">
                {metrics.alerts.map((alert, index) => (
                  <div key={index} className={`alert-item ${alert.severity}`}>
                    <AlertTriangle size={16} />
                    <span>{alert.message}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-alerts">No active alerts</p>
            )}
          </div>
        </div>
      )}

      {/* System Resources */}
      {metrics && metrics.cpu && metrics.memory && metrics.disk && metrics.network && (
        <div className="metrics-grid">
          {/* CPU */}
          <div className="metric-card">
            <div className="metric-header">
              <Cpu size={24} />
              <h3>CPU Usage</h3>
            </div>
            <div className="metric-value">{metrics.cpu.usage}%</div>
            <div className="metric-bar">
              <div 
                className="metric-fill" 
                style={{ 
                  width: `${metrics.cpu.usage}%`,
                  background: metrics.cpu.usage > 80 ? '#ef4444' : metrics.cpu.usage > 60 ? '#f59e0b' : '#10b981'
                }}
              />
            </div>
            <div className="metric-details">
              <div className="detail-item">
                <span>Cores:</span>
                <strong>{metrics.cpu.cores}</strong>
              </div>
              <div className="detail-item">
                <span>Speed:</span>
                <strong>{metrics.cpu.speed} MHz</strong>
              </div>
              {metrics.cpu.temperature && (
                <div className="detail-item">
                  <span>Temp:</span>
                  <strong>{metrics.cpu.temperature}°C</strong>
                </div>
              )}
            </div>
          </div>

          {/* Memory */}
          <div className="metric-card">
            <div className="metric-header">
              <Database size={24} />
              <h3>Memory Usage</h3>
            </div>
            <div className="metric-value">{metrics.memory.usagePercent}%</div>
            <div className="metric-bar">
              <div 
                className="metric-fill" 
                style={{ 
                  width: `${metrics.memory.usagePercent}%`,
                  background: metrics.memory.usagePercent > 85 ? '#ef4444' : metrics.memory.usagePercent > 70 ? '#f59e0b' : '#10b981'
                }}
              />
            </div>
            <div className="metric-details">
              <div className="detail-item">
                <span>Used:</span>
                <strong>{formatBytes(metrics.memory.used)}</strong>
              </div>
              <div className="detail-item">
                <span>Free:</span>
                <strong>{formatBytes(metrics.memory.free)}</strong>
              </div>
              <div className="detail-item">
                <span>Total:</span>
                <strong>{formatBytes(metrics.memory.total)}</strong>
              </div>
            </div>
          </div>

          {/* Disk */}
          <div className="metric-card">
            <div className="metric-header">
              <HardDrive size={24} />
              <h3>Disk Usage</h3>
            </div>
            <div className="metric-value">{metrics.disk.usagePercent}%</div>
            <div className="metric-bar">
              <div 
                className="metric-fill" 
                style={{ 
                  width: `${metrics.disk.usagePercent}%`,
                  background: metrics.disk.usagePercent > 90 ? '#ef4444' : metrics.disk.usagePercent > 75 ? '#f59e0b' : '#10b981'
                }}
              />
            </div>
            <div className="metric-details">
              <div className="detail-item">
                <span>Used:</span>
                <strong>{formatBytes(metrics.disk.used)}</strong>
              </div>
              <div className="detail-item">
                <span>Free:</span>
                <strong>{formatBytes(metrics.disk.free)}</strong>
              </div>
              <div className="detail-item">
                <span>Total:</span>
                <strong>{formatBytes(metrics.disk.total)}</strong>
              </div>
            </div>
          </div>

          {/* Network */}
          <div className="metric-card">
            <div className="metric-header">
              <Wifi size={24} />
              <h3>Network</h3>
            </div>
            <div className="metric-value">{metrics.network.interfaces ? metrics.network.interfaces.length : 0}</div>
            <div className="metric-label">Active Interfaces</div>
            <div className="metric-details">
              <div className="detail-item">
                <span>Hostname:</span>
                <strong>{metrics.network.hostname || 'Unknown'}</strong>
              </div>
              {metrics.network.interfaces && Array.isArray(metrics.network.interfaces) && metrics.network.interfaces.map((iface, index) => (
                <div key={index} className="detail-item">
                  <span>{iface.name}:</span>
                  <strong>{iface.address}</strong>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Real-Time Performance Charts */}
      {historicalData.timestamps.length > 0 && (
        <div className="performance-charts">
          <h2><BarChart3 size={24} /> Real-Time Performance</h2>
          
          <div className="charts-grid">
            <div className="chart-card">
              <h3><Cpu size={20} /> CPU Usage Over Time</h3>
              <Line
                data={{
                  labels: historicalData.timestamps,
                  datasets: [{
                    label: 'CPU Usage (%)',
                    data: historicalData.cpu,
                    borderColor: 'rgb(99, 102, 241)',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                    pointHoverRadius: 5
                  }]
                }}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: { display: false },
                    tooltip: {
                      mode: 'index',
                      intersect: false,
                    }
                  },
                  scales: {
                    y: {
                      beginAtZero: true,
                      max: 100,
                      ticks: {
                        callback: (value) => value + '%'
                      }
                    },
                    x: {
                      display: false
                    }
                  },
                  interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                  }
                }}
              />
            </div>

            <div className="chart-card">
              <h3><Database size={20} /> Memory Usage Over Time</h3>
              <Line
                data={{
                  labels: historicalData.timestamps,
                  datasets: [{
                    label: 'Memory Usage (%)',
                    data: historicalData.memory,
                    borderColor: 'rgb(16, 185, 129)',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                    pointHoverRadius: 5
                  }]
                }}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: { display: false },
                    tooltip: {
                      mode: 'index',
                      intersect: false,
                    }
                  },
                  scales: {
                    y: {
                      beginAtZero: true,
                      max: 100,
                      ticks: {
                        callback: (value) => value + '%'
                      }
                    },
                    x: {
                      display: false
                    }
                  },
                  interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                  }
                }}
              />
            </div>

            <div className="chart-card">
              <h3><HardDrive size={20} /> Disk Usage Over Time</h3>
              <Line
                data={{
                  labels: historicalData.timestamps,
                  datasets: [{
                    label: 'Disk Usage (%)',
                    data: historicalData.disk,
                    borderColor: 'rgb(245, 158, 11)',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                    pointHoverRadius: 5
                  }]
                }}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: { display: false },
                    tooltip: {
                      mode: 'index',
                      intersect: false,
                    }
                  },
                  scales: {
                    y: {
                      beginAtZero: true,
                      max: 100,
                      ticks: {
                        callback: (value) => value + '%'
                      }
                    },
                    x: {
                      display: false
                    }
                  },
                  interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                  }
                }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Process Monitor */}
      <div className="process-monitor-section">
        <div className="section-header">
          <h2><List size={24} /> Process Monitor</h2>
          <button 
            className="toggle-processes-btn"
            onClick={() => setShowProcesses(!showProcesses)}
          >
            {showProcesses ? <X size={20} /> : <Monitor size={20} />}
            {showProcesses ? 'Hide Processes' : 'Show Processes'}
          </button>
        </div>

        {showProcesses && Array.isArray(processes) && processes.length > 0 && (
          <div className="processes-table-container">
            <table className="processes-table">
              <thead>
                <tr>
                  <th>Process Name</th>
                  <th>PID</th>
                  <th>CPU %</th>
                  <th>Memory</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {processes.slice(0, 15).map((proc, index) => (
                  <tr key={index}>
                    <td className="process-name">{proc.name}</td>
                    <td>{proc.pid}</td>
                    <td>
                      <span className={`cpu-usage ${proc.cpu > 50 ? 'high' : proc.cpu > 25 ? 'medium' : 'low'}`}>
                        {proc.cpu.toFixed(1)}%
                      </span>
                    </td>
                    <td>{formatBytes(proc.memory)}</td>
                    <td>
                      <span className={`status-badge ${proc.status}`}>
                        {proc.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Process Metrics */}
      {metrics && metrics.processes && (
        <div className="process-metrics">
          <h2><Zap size={24} /> Process Information</h2>
          <div className="process-grid">
            <div className="process-item">
              <Clock size={20} />
              <div>
                <div className="process-label">Uptime</div>
                <div className="process-value">{formatUptime(metrics.processes.uptime)}</div>
              </div>
            </div>
            <div className="process-item">
              <Database size={20} />
              <div>
                <div className="process-label">Heap Used</div>
                <div className="process-value">{formatBytes(metrics.processes.memory.heapUsed)}</div>
              </div>
            </div>
            <div className="process-item">
              <Activity size={20} />
              <div>
                <div className="process-label">Platform</div>
                <div className="process-value">{metrics.processes.platform} ({metrics.processes.arch})</div>
              </div>
            </div>
            <div className="process-item">
              <BarChart3 size={20} />
              <div>
                <div className="process-label">Node Version</div>
                <div className="process-value">{metrics.processes.version}</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Analytics Dashboard */}
      {dashboard && (
        <div className="analytics-section">
          <h2><BarChart3 size={24} /> Analytics Overview ({timeRange})</h2>
          
          <div className="analytics-grid">
            <div className="analytics-card">
              <div className="analytics-icon">
                <Activity size={32} />
              </div>
              <div className="analytics-content">
                <div className="analytics-value">{dashboard.overview.totalEvents.toLocaleString()}</div>
                <div className="analytics-label">Total Events</div>
              </div>
            </div>

            <div className="analytics-card">
              <div className="analytics-icon">
                <TrendingUp size={32} />
              </div>
              <div className="analytics-content">
                <div className="analytics-value">{dashboard.overview.totalPageViews.toLocaleString()}</div>
                <div className="analytics-label">Page Views</div>
              </div>
            </div>

            <div className="analytics-card">
              <div className="analytics-icon">
                <Cpu size={32} />
              </div>
              <div className="analytics-content">
                <div className="analytics-value">{dashboard.overview.activeSessions.toLocaleString()}</div>
                <div className="analytics-label">Active Sessions</div>
              </div>
            </div>

            <div className="analytics-card">
              <div className="analytics-icon">
                <AlertTriangle size={32} />
              </div>
              <div className="analytics-content">
                <div className="analytics-value">{dashboard.overview.totalErrors.toLocaleString()}</div>
                <div className="analytics-label">Errors</div>
              </div>
            </div>
          </div>

          {/* Top Events */}
          {dashboard.topEvents && Array.isArray(dashboard.topEvents) && dashboard.topEvents.length > 0 && (
            <div className="top-items">
              <h3>Top Events</h3>
              <div className="top-items-list">
                {dashboard.topEvents.slice(0, 5).map((event, index) => (
                  <div key={index} className="top-item">
                    <span className="top-item-name">{event.event_name}</span>
                    <span className="top-item-count">{event.count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Top Pages */}
          {dashboard.topPages && Array.isArray(dashboard.topPages) && dashboard.topPages.length > 0 && (
            <div className="top-items">
              <h3>Top Pages</h3>
              <div className="top-items-list">
                {dashboard.topPages.slice(0, 5).map((page, index) => (
                  <div key={index} className="top-item">
                    <span className="top-item-name">{page.page_url}</span>
                    <span className="top-item-count">{page.views}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default PerformanceMetrics;
