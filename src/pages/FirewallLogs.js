import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, Search, Download, Trash2, Filter,
  AlertTriangle, Activity, Eye, FileText, Database,
  TrendingUp, BarChart3, Globe, Server, Lock, Zap
} from 'lucide-react';
import toast from 'react-hot-toast';
import firewallLogger from '../services/firewallLogger';
import ExportModal from '../components/ExportModal';
import './FirewallLogs.css';
import './FirewallLogs-enhanced.css';

const FirewallLogs = () => {
  const [logs, setLogs] = useState([]);
  const [filteredLogs, setFilteredLogs] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);
  const [forensicAnalysis, setForensicAnalysis] = useState(null);
  const [showForensics, setShowForensics] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  
  // Filters
  const [filters, setFilters] = useState({
    severity: 'all',
    threatType: 'all',
    blocked: 'all',
    dateRange: 'all'
  });
  
  // Tab state
  const [activeTab, setActiveTab] = useState('logs'); // logs, statistics, forensics, alerts

  useEffect(() => {
    loadData();
    
    // Subscribe to real-time updates
    const unsubscribe = firewallLogger.subscribe((event, data) => {
      if (event === 'new_log') {
        setLogs(prev => [data, ...prev]);
      } else if (event === 'logs_cleared') {
        setLogs([]);
        setFilteredLogs([]);
      }
    });
    
    return unsubscribe;
  }, []);

  useEffect(() => {
    applyFilters();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [logs, filters, searchQuery]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [logsData, statsData] = await Promise.all([
        firewallLogger.getLogs({ limit: 1000 }).catch(err => {
          console.error('Error loading logs:', err);
          return [];
        }),
        firewallLogger.getStatistics().catch(err => {
          console.error('Error loading statistics:', err);
          return {
            totalThreats: 0,
            threatsBlocked: 0,
            criticalThreats: 0,
            highThreats: 0,
            mediumThreats: 0,
            lowThreats: 0,
            blockRate: 0,
            topThreatTypes: [],
            topSourceIPs: [],
            topTargetPorts: [],
            timeline: [],
            severityDistribution: { critical: 0, high: 0, medium: 0, low: 0 }
          };
        })
      ]);
      
      setLogs(logsData || []);
      setFilteredLogs(logsData || []);
      setStatistics(statsData);
      
      if (logsData.length === 0) {
        console.log('No logs found in database. Start the firewall or generate demo data.');
      }
    } catch (error) {
      console.error('Failed to load logs:', error);
      toast.error('Failed to load firewall logs: ' + (error.message || 'Internal error'));
      // Set empty data to prevent UI crashes
      setLogs([]);
      setFilteredLogs([]);
      setStatistics({
        totalThreats: 0,
        threatsBlocked: 0,
        criticalThreats: 0,
        highThreats: 0,
        mediumThreats: 0,
        lowThreats: 0,
        blockRate: 0,
        topThreatTypes: [],
        topSourceIPs: [],
        topTargetPorts: [],
        timeline: [],
        severityDistribution: { critical: 0, high: 0, medium: 0, low: 0 }
      });
    } finally {
      setLoading(false);
    }
  };
  
  const generateDemoData = async () => {
    try {
      toast.loading('Generating demo threat logs...', { id: 'demo' });
      
      const demoLogs = [
        {
          threatType: 'malware',
          severity: 'critical',
          sourceIP: '192.168.1.100',
          destinationIP: '10.0.0.5',
          port: 443,
          protocol: 'HTTPS',
          action: 'blocked',
          signatureName: 'Trojan.Generic.KD.12345',
          blocked: true,
          confidence: 0.98,
          riskScore: 95,
          description: 'Malicious payload detected in HTTPS traffic'
        },
        {
          threatType: 'intrusion',
          severity: 'high',
          sourceIP: '203.0.113.42',
          destinationIP: '10.0.0.5',
          port: 22,
          protocol: 'SSH',
          action: 'blocked',
          signatureName: 'SSH.BruteForce.Attempt',
          blocked: true,
          confidence: 0.95,
          riskScore: 88,
          description: 'Multiple failed SSH login attempts detected'
        },
        {
          threatType: 'ddos',
          severity: 'critical',
          sourceIP: '198.51.100.23',
          destinationIP: '10.0.0.1',
          port: 80,
          protocol: 'HTTP',
          action: 'blocked',
          signatureName: 'DDoS.SYN.Flood',
          blocked: true,
          confidence: 0.99,
          riskScore: 98,
          description: 'SYN flood attack detected'
        },
        {
          threatType: 'exploit',
          severity: 'high',
          sourceIP: '172.16.0.99',
          destinationIP: '10.0.0.3',
          port: 8080,
          protocol: 'HTTP',
          action: 'blocked',
          signatureName: 'SQL.Injection.Attempt',
          blocked: true,
          confidence: 0.92,
          riskScore: 85,
          description: 'SQL injection pattern detected in request'
        },
        {
          threatType: 'reconnaissance',
          severity: 'medium',
          sourceIP: '209.85.231.104',
          destinationIP: '10.0.0.1',
          port: 3389,
          protocol: 'RDP',
          action: 'detected',
          signatureName: 'Port.Scan.Sequential',
          blocked: false,
          confidence: 0.78,
          riskScore: 65,
          description: 'Sequential port scanning detected'
        }
      ];
      
      for (const log of demoLogs) {
        await firewallLogger.logThreat(log);
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      toast.success('Successfully generated 5 demo threat logs!', { id: 'demo' });
      await loadData();
    } catch (error) {
      toast.error('Failed to generate demo data: ' + error.message, { id: 'demo' });
    }
  };

  const applyFilters = () => {
    let filtered = [...logs];
    
    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(log =>
        log.threatType?.toLowerCase().includes(query) ||
        log.sourceIP?.toLowerCase().includes(query) ||
        log.destinationIP?.toLowerCase().includes(query) ||
        log.signatureName?.toLowerCase().includes(query)
      );
    }
    
    // Severity filter
    if (filters.severity !== 'all') {
      filtered = filtered.filter(log => log.severity === filters.severity);
    }
    
    // Blocked filter
    if (filters.blocked !== 'all') {
      const isBlocked = filters.blocked === 'blocked';
      filtered = filtered.filter(log => log.blocked === isBlocked);
    }
    
    // Date range filter
    if (filters.dateRange !== 'all') {
      const now = new Date();
      let cutoff = new Date();
      
      switch (filters.dateRange) {
        case 'today':
          cutoff.setHours(0, 0, 0, 0);
          break;
        case 'week':
          cutoff.setDate(now.getDate() - 7);
          break;
        case 'month':
          cutoff.setMonth(now.getMonth() - 1);
          break;
        default:
          break;
      }
      
      filtered = filtered.filter(log => new Date(log.timestamp) >= cutoff);
    }
    
    setFilteredLogs(filtered);
  };

  const handleSearch = async () => {
    if (searchQuery.trim()) {
      setLoading(true);
      const results = await firewallLogger.searchLogs(searchQuery);
      setFilteredLogs(results);
      setLoading(false);
    } else {
      applyFilters();
    }
  };

  const handleExport = async (format, exportFilters, options) => {
    try {
      const result = await firewallLogger.exportLogs(format, exportFilters, options);
      return result;
    } catch (error) {
      throw error;
    }
  };

  const handleClearLogs = async () => {
    if (window.confirm('Are you sure you want to delete ALL logs? This cannot be undone.')) {
      try {
        await firewallLogger.clearLogs();
        toast.success('All logs have been cleared', { icon: '🗑️' });
        setLogs([]);
        setFilteredLogs([]);
      } catch (error) {
        toast.error('Failed to clear logs: ' + error.message);
      }
    }
  };

  const handleViewForensics = async (log) => {
    setSelectedLog(log);
    setShowForensics(true);
    setLoading(true);
    
    try {
      const analysis = await firewallLogger.getForensicAnalysis(log.id);
      setForensicAnalysis(analysis);
    } catch (error) {
      console.error('Failed to load forensic analysis:', error);
    }
    
    setLoading(false);
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#dc2626',
      high: '#f59e0b',
      medium: '#3b82f6',
      low: '#10b981'
    };
    return colors[severity] || '#6b7280';
  };

  const getSeverityIcon = (severity) => {
    if (severity === 'critical') return '🔴';
    if (severity === 'high') return '🟠';
    if (severity === 'medium') return '🟡';
    return '🟢';
  };

  if (loading && logs.length === 0) {
    return (
      <div className="firewall-logs">
        <div className="logs-header">
          <div className="header-title">
            <Shield size={32} />
            <div>
              <h2>🛡️ Firewall Threat Logs & Forensic Analysis</h2>
              <p>Initializing firewall logging system...</p>
            </div>
          </div>
        </div>
        <div className="loading-container">
          <Activity className="loading-spinner" size={48} />
          <p>Loading forensic logs...</p>
        </div>
      </div>
    );
  }
  
  // Empty state - no logs in database
  if (!loading && logs.length === 0) {
    return (
      <div className="firewall-logs">
        <div className="logs-header">
          <div className="header-title">
            <Shield size={32} />
            <div>
              <h2>🛡️ Firewall Threat Logs & Forensic Analysis</h2>
              <p>0 threat events · Real-time monitoring ready</p>
            </div>
          </div>
          
          <div className="header-actions">
            <button onClick={() => loadData()} className="btn-refresh">
              <Activity size={18} /> Refresh
            </button>
          </div>
        </div>
        
        <div className="empty-state" style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '60px 20px',
          textAlign: 'center'
        }}>
          <Shield size={64} style={{ color: '#9ca3af', marginBottom: '20px' }} />
          <h3 style={{ fontSize: '24px', marginBottom: '12px', color: '#374151' }}>No Threat Logs Yet</h3>
          <p style={{ color: '#6b7280', marginBottom: '24px', maxWidth: '500px' }}>
            The firewall is active and monitoring network traffic. Threat logs will appear here when suspicious activity is detected.
          </p>
          <button 
            onClick={generateDemoData}
            style={{
              padding: '12px 24px',
              background: 'linear-gradient(135deg, #7c3aed 0%, #6366f1 100%)',
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              fontSize: '14px',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              boxShadow: '0 4px 12px rgba(124, 58, 237, 0.3)'
            }}
          >
            <Zap size={18} />
            Generate Demo Data
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="firewall-logs">
      {/* Header */}
      <div className="logs-header">
        <div className="header-title">
          <Shield size={32} />
          <div>
            <h2>🛡️ Firewall Threat Logs & Forensic Analysis</h2>
            <p>{filteredLogs.length} threat events · Real-time monitoring active</p>
          </div>
        </div>
        
        <div className="header-actions">
          <button onClick={() => loadData()} className="btn-refresh">
            <Activity size={18} /> Refresh
          </button>
          <button onClick={() => setShowExportModal(true)} className="btn-export">
            <Download size={18} /> Export
          </button>
          <button onClick={handleClearLogs} className="btn-danger">
            <Trash2 size={18} /> Clear All
          </button>
        </div>
      </div>

      {/* Statistics Cards */}
      {statistics && (
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon" style={{ background: '#7c3aed' }}>
              <Database size={24} />
            </div>
            <div className="stat-content">
              <div className="stat-value">{statistics.totalThreats.toLocaleString()}</div>
              <div className="stat-label">Total Threats</div>
            </div>
          </div>
          
          <div className="stat-card">
            <div className="stat-icon" style={{ background: '#10b981' }}>
              <Shield size={24} />
            </div>
            <div className="stat-content">
              <div className="stat-value">{statistics.threatsBlocked.toLocaleString()}</div>
              <div className="stat-label">Threats Blocked</div>
            </div>
          </div>
          
          <div className="stat-card">
            <div className="stat-icon" style={{ background: '#dc2626' }}>
              <AlertTriangle size={24} />
            </div>
            <div className="stat-content">
              <div className="stat-value">{statistics.criticalThreats}</div>
              <div className="stat-label">Critical Threats</div>
            </div>
          </div>
          
          <div className="stat-card">
            <div className="stat-icon" style={{ background: '#3b82f6' }}>
              <TrendingUp size={24} />
            </div>
            <div className="stat-content">
              <div className="stat-value">
                {statistics.threatsBlocked > 0 
                  ? Math.round((statistics.threatsBlocked / statistics.totalThreats) * 100)
                  : 0}%
              </div>
              <div className="stat-label">Block Rate</div>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="logs-tabs">
        <button 
          className={activeTab === 'logs' ? 'tab-active' : ''} 
          onClick={() => setActiveTab('logs')}
        >
          <FileText size={18} /> Threat Logs
        </button>
        <button 
          className={activeTab === 'statistics' ? 'tab-active' : ''} 
          onClick={() => setActiveTab('statistics')}
        >
          <BarChart3 size={18} /> Statistics
        </button>
        <button 
          className={activeTab === 'forensics' ? 'tab-active' : ''} 
          onClick={() => setActiveTab('forensics')}
        >
          <Eye size={18} /> Forensic Analysis
        </button>
      </div>

      {/* Search and Filters */}
      <div className="logs-controls">
        <div className="search-bar">
          <Search size={20} />
          <input
            type="text"
            placeholder="Search logs by IP, threat type, signature..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
          />
          <button onClick={handleSearch}>Search</button>
        </div>
        
        <div className="filters">
          <Filter size={18} />
          
          <select value={filters.severity} onChange={(e) => setFilters({...filters, severity: e.target.value})}>
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          
          <select value={filters.blocked} onChange={(e) => setFilters({...filters, blocked: e.target.value})}>
            <option value="all">All Actions</option>
            <option value="blocked">Blocked Only</option>
            <option value="detected">Detected Only</option>
          </select>
          
          <select value={filters.dateRange} onChange={(e) => setFilters({...filters, dateRange: e.target.value})}>
            <option value="all">All Time</option>
            <option value="today">Today</option>
            <option value="week">Last 7 Days</option>
            <option value="month">Last 30 Days</option>
          </select>
        </div>
      </div>

      {/* Content based on active tab */}
      {activeTab === 'logs' && (
        <div className="logs-content">
          {filteredLogs.length === 0 ? (
            <div className="empty-state">
              <Shield size={64} />
              <h3>No threat logs found</h3>
              <p>Your firewall is protecting you. Threats will appear here when detected.</p>
            </div>
          ) : (
            <div className="logs-table-container">
              <table className="logs-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Severity</th>
                    <th>Threat Type</th>
                    <th>Source IP</th>
                    <th>Destination</th>
                    <th>Signature</th>
                    <th>Action</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.map((log) => (
                    <tr key={log.id} className={`severity-${log.severity}`}>
                      <td className="timestamp-cell">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td>
                        <span className="severity-badge" style={{ background: getSeverityColor(log.severity) }}>
                          {getSeverityIcon(log.severity)} {log.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="threat-type-cell">
                        <code>{log.threatType}</code>
                      </td>
                      <td className="ip-cell">
                        <Globe size={14} /> {log.sourceIP}
                      </td>
                      <td className="ip-cell">
                        <Server size={14} /> {log.destinationIP}:{log.port || 'N/A'}
                      </td>
                      <td>{log.signatureName}</td>
                      <td>
                        {log.blocked ? (
                          <span className="action-badge blocked">
                            <Lock size={14} /> Blocked
                          </span>
                        ) : (
                          <span className="action-badge detected">
                            <AlertTriangle size={14} /> Detected
                          </span>
                        )}
                      </td>
                      <td>
                        <button 
                          className="btn-view-forensics"
                          onClick={() => handleViewForensics(log)}
                        >
                          <Eye size={16} /> Forensics
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'statistics' && statistics && (
        <div className="statistics-content">
          {/* Threat Overview Banner */}
          <div className="threat-overview-banner">
            <div className="threat-score-section">
              <div className="threat-score-label">Overall Threat Score</div>
              <div className="threat-score-circle">
                <svg viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="45" fill="none" stroke="#e5e7eb" strokeWidth="10"/>
                  <circle 
                    cx="50" 
                    cy="50" 
                    r="45" 
                    fill="none" 
                    stroke={statistics.totalThreats > 100 ? '#dc2626' : statistics.totalThreats > 50 ? '#f59e0b' : '#10b981'}
                    strokeWidth="10"
                    strokeDasharray={`${(statistics.totalThreats > 500 ? 100 : (statistics.totalThreats / 5))} 283`}
                    transform="rotate(-90 50 50)"
                  />
                </svg>
                <div className="threat-score-value">
                  {statistics.totalThreats > 500 ? 'HIGH' : statistics.totalThreats > 200 ? 'MEDIUM' : 'LOW'}
                </div>
              </div>
              <div className="threat-score-desc">
                {statistics.totalThreats} total threats detected
              </div>
            </div>
            
            <div className="threat-summary-stats">
              <div className="summary-stat critical-stat">
                <AlertTriangle size={24} />
                <div className="summary-stat-content">
                  <div className="summary-stat-value">{statistics.criticalThreats || 0}</div>
                  <div className="summary-stat-label">Critical</div>
                </div>
              </div>
              <div className="summary-stat high-stat">
                <Zap size={24} />
                <div className="summary-stat-content">
                  <div className="summary-stat-value">{statistics.highThreats || 0}</div>
                  <div className="summary-stat-label">High</div>
                </div>
              </div>
              <div className="summary-stat medium-stat">
                <Activity size={24} />
                <div className="summary-stat-content">
                  <div className="summary-stat-value">{statistics.mediumThreats || 0}</div>
                  <div className="summary-stat-label">Medium</div>
                </div>
              </div>
              <div className="summary-stat low-stat">
                <Shield size={24} />
                <div className="summary-stat-content">
                  <div className="summary-stat-value">{statistics.lowThreats || 0}</div>
                  <div className="summary-stat-label">Low</div>
                </div>
              </div>
            </div>
            
            <div className="threat-metrics-quick">
              <div className="quick-metric">
                <div className="quick-metric-icon">🛡️</div>
                <div className="quick-metric-value">{statistics.blockRate || 0}%</div>
                <div className="quick-metric-label">Block Rate</div>
              </div>
              <div className="quick-metric">
                <div className="quick-metric-icon">🌍</div>
                <div className="quick-metric-value">{new Set(filteredLogs.map(l => l.sourceIP)).size}</div>
                <div className="quick-metric-label">Unique IPs</div>
              </div>
              <div className="quick-metric">
                <div className="quick-metric-icon">⚡</div>
                <div className="quick-metric-value">{filteredLogs.filter(l => l.action === 'blocked').length}</div>
                <div className="quick-metric-label">Blocked</div>
              </div>
            </div>
          </div>

          {/* Real-time Metrics Grid */}
          <div className="metrics-grid">
            <div className="metric-card critical">
              <div className="metric-icon">
                <AlertTriangle size={32} />
              </div>
              <div className="metric-content">
                <div className="metric-label">Critical Threats</div>
                <div className="metric-value">{statistics.criticalThreats || 0}</div>
                <div className="metric-trend">⚠️ Requires immediate action</div>
              </div>
            </div>
            
            <div className="metric-card high">
              <div className="metric-icon">
                <Zap size={32} />
              </div>
              <div className="metric-content">
                <div className="metric-label">High Priority</div>
                <div className="metric-value">{statistics.highThreats || 0}</div>
                <div className="metric-trend">📋 Review recommended</div>
              </div>
            </div>
            
            <div className="metric-card medium">
              <div className="metric-icon">
                <Activity size={32} />
              </div>
              <div className="metric-content">
                <div className="metric-label">Medium Priority</div>
                <div className="metric-value">{statistics.mediumThreats || 0}</div>
                <div className="metric-trend">👁️ Monitor activity</div>
              </div>
            </div>
            
            <div className="metric-card success">
              <div className="metric-icon">
                <Shield size={32} />
              </div>
              <div className="metric-content">
                <div className="metric-label">Blocks Success Rate</div>
                <div className="metric-value">{statistics.blockRate || 0}%</div>
                <div className="metric-trend">✅ Protection active</div>
              </div>
            </div>
          </div>

          {/* Threat Distribution Charts */}
          <div className="charts-row">
            <div className="stat-section chart-section">
              <h3><BarChart3 size={20} /> Threat Distribution by Severity</h3>
              <div className="severity-chart-enhanced">
                <div className="chart-row">
                  <div className="chart-label">Critical</div>
                  <div className="chart-bar-container">
                    <div className="chart-bar critical" style={{ width: `${statistics.totalThreats > 0 ? (statistics.criticalThreats / statistics.totalThreats) * 100 : 0}%` }}>
                      <span className="chart-value">{statistics.criticalThreats || 0}</span>
                    </div>
                  </div>
                  <div className="chart-percentage">{statistics.totalThreats > 0 ? Math.round((statistics.criticalThreats / statistics.totalThreats) * 100) : 0}%</div>
                </div>
                <div className="chart-row">
                  <div className="chart-label">High</div>
                  <div className="chart-bar-container">
                    <div className="chart-bar high" style={{ width: `${statistics.totalThreats > 0 ? (statistics.highThreats / statistics.totalThreats) * 100 : 0}%` }}>
                      <span className="chart-value">{statistics.highThreats || 0}</span>
                    </div>
                  </div>
                  <div className="chart-percentage">{statistics.totalThreats > 0 ? Math.round((statistics.highThreats / statistics.totalThreats) * 100) : 0}%</div>
                </div>
                <div className="chart-row">
                  <div className="chart-label">Medium</div>
                  <div className="chart-bar-container">
                    <div className="chart-bar medium" style={{ width: `${statistics.totalThreats > 0 ? (statistics.mediumThreats / statistics.totalThreats) * 100 : 0}%` }}>
                      <span className="chart-value">{statistics.mediumThreats || 0}</span>
                    </div>
                  </div>
                  <div className="chart-percentage">{statistics.totalThreats > 0 ? Math.round((statistics.mediumThreats / statistics.totalThreats) * 100) : 0}%</div>
                </div>
                <div className="chart-row">
                  <div className="chart-label">Low</div>
                  <div className="chart-bar-container">
                    <div className="chart-bar low" style={{ width: `${statistics.totalThreats > 0 ? (statistics.lowThreats / statistics.totalThreats) * 100 : 0}%` }}>
                      <span className="chart-value">{statistics.lowThreats || 0}</span>
                    </div>
                  </div>
                  <div className="chart-percentage">{statistics.totalThreats > 0 ? Math.round((statistics.lowThreats / statistics.totalThreats) * 100) : 0}%</div>
                </div>
              </div>
            </div>
            
            <div className="stat-section chart-section">
              <h3><TrendingUp size={20} /> Attack Pattern Analysis</h3>
              <div className="attack-patterns">
                <div className="pattern-item">
                  <div className="pattern-icon"><Globe size={24} /></div>
                  <div className="pattern-details">
                    <div className="pattern-name">Web-based Attacks</div>
                    <div className="pattern-count">{filteredLogs.filter(l => l.threatType?.includes('sql') || l.threatType?.includes('xss') || l.threatType?.includes('injection')).length}</div>
                    <div className="pattern-bar">
                      <div style={{ width: '75%', background: '#f59e0b' }}></div>
                    </div>
                  </div>
                </div>
                <div className="pattern-item">
                  <div className="pattern-icon"><Server size={24} /></div>
                  <div className="pattern-details">
                    <div className="pattern-name">Network Intrusions</div>
                    <div className="pattern-count">{filteredLogs.filter(l => l.threatType?.includes('scan') || l.threatType?.includes('brute')).length}</div>
                    <div className="pattern-bar">
                      <div style={{ width: '60%', background: '#dc2626' }}></div>
                    </div>
                  </div>
                </div>
                <div className="pattern-item">
                  <div className="pattern-icon"><Lock size={24} /></div>
                  <div className="pattern-details">
                    <div className="pattern-name">Malware Attempts</div>
                    <div className="pattern-count">{filteredLogs.filter(l => l.threatType?.includes('malware') || l.threatType?.includes('ransomware')).length}</div>
                    <div className="pattern-bar">
                      <div style={{ width: '45%', background: '#ef4444' }}></div>
                    </div>
                  </div>
                </div>
                <div className="pattern-item">
                  <div className="pattern-icon"><Database size={24} /></div>
                  <div className="pattern-details">
                    <div className="pattern-name">Data Exfiltration</div>
                    <div className="pattern-count">{filteredLogs.filter(l => l.threatType?.includes('exfil')).length}</div>
                    <div className="pattern-bar">
                      <div style={{ width: '30%', background: '#f59e0b' }}></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Top Lists */}
          <div className="charts-row">
            <div className="stat-section">
              <h3>🎯 Top Threat Types</h3>
              <div className="top-list-enhanced">
                {statistics.topThreatTypes && statistics.topThreatTypes.length > 0 ? (
                  statistics.topThreatTypes.slice(0, 8).map((item, index) => (
                    <div key={index} className="top-item-enhanced">
                      <div className="top-rank" style={{ background: index === 0 ? '#dc2626' : index === 1 ? '#f59e0b' : index === 2 ? '#3b82f6' : '#6b7280' }}>
                        #{index + 1}
                      </div>
                      <div className="top-details">
                        <div className="top-name">{item.name}</div>
                        <div className="top-bar">
                          <div style={{ width: `${(item.count / statistics.topThreatTypes[0].count) * 100}%` }}></div>
                        </div>
                      </div>
                      <div className="top-count">{item.count}</div>
                    </div>
                  ))
                ) : (
                  <div className="empty-state-small">No threat data available</div>
                )}
              </div>
            </div>
            
            <div className="stat-section">
              <h3>🌐 Top Attacking IPs</h3>
              <div className="top-list-enhanced">
                {statistics.topSourceIPs && statistics.topSourceIPs.length > 0 ? (
                  statistics.topSourceIPs.slice(0, 8).map((item, index) => (
                    <div key={index} className="top-item-enhanced">
                      <div className="top-rank" style={{ background: index === 0 ? '#dc2626' : index === 1 ? '#f59e0b' : index === 2 ? '#3b82f6' : '#6b7280' }}>
                        #{index + 1}
                      </div>
                      <div className="top-details">
                        <div className="top-name"><Globe size={14} /> {item.name}</div>
                        <div className="top-bar">
                          <div style={{ width: `${(item.count / statistics.topSourceIPs[0].count) * 100}%` }}></div>
                        </div>
                      </div>
                      <div className="top-count">{item.count}</div>
                    </div>
                  ))
                ) : (
                  <div className="empty-state-small">No IP data available</div>
                )}
              </div>
            </div>
          </div>

          {/* Protocol & Port Analysis */}
          <div className="stat-section">
            <h3>🔌 Protocol & Port Distribution</h3>
            <div className="protocol-grid">
              <div className="protocol-card">
                <div className="protocol-name">HTTPS</div>
                <div className="protocol-value">{filteredLogs.filter(l => l.port === 443).length}</div>
                <div className="protocol-percentage">{filteredLogs.length > 0 ? Math.round((filteredLogs.filter(l => l.port === 443).length / filteredLogs.length) * 100) : 0}%</div>
              </div>
              <div className="protocol-card">
                <div className="protocol-name">HTTP</div>
                <div className="protocol-value">{filteredLogs.filter(l => l.port === 80).length}</div>
                <div className="protocol-percentage">{filteredLogs.length > 0 ? Math.round((filteredLogs.filter(l => l.port === 80).length / filteredLogs.length) * 100) : 0}%</div>
              </div>
              <div className="protocol-card">
                <div className="protocol-name">SSH</div>
                <div className="protocol-value">{filteredLogs.filter(l => l.port === 22).length}</div>
                <div className="protocol-percentage">{filteredLogs.length > 0 ? Math.round((filteredLogs.filter(l => l.port === 22).length / filteredLogs.length) * 100) : 0}%</div>
              </div>
              <div className="protocol-card">
                <div className="protocol-name">RDP</div>
                <div className="protocol-value">{filteredLogs.filter(l => l.port === 3389).length}</div>
                <div className="protocol-percentage">{filteredLogs.length > 0 ? Math.round((filteredLogs.filter(l => l.port === 3389).length / filteredLogs.length) * 100) : 0}%</div>
              </div>
              <div className="protocol-card">
                <div className="protocol-name">FTP</div>
                <div className="protocol-value">{filteredLogs.filter(l => l.port === 21).length}</div>
                <div className="protocol-percentage">{filteredLogs.length > 0 ? Math.round((filteredLogs.filter(l => l.port === 21).length / filteredLogs.length) * 100) : 0}%</div>
              </div>
              <div className="protocol-card">
                <div className="protocol-name">DNS</div>
                <div className="protocol-value">{filteredLogs.filter(l => l.port === 53).length}</div>
                <div className="protocol-percentage">{filteredLogs.length > 0 ? Math.round((filteredLogs.filter(l => l.port === 53).length / filteredLogs.length) * 100) : 0}%</div>
              </div>
              <div className="protocol-card">
                <div className="protocol-name">SMB</div>
                <div className="protocol-value">{filteredLogs.filter(l => l.port === 445).length}</div>
                <div className="protocol-percentage">{filteredLogs.length > 0 ? Math.round((filteredLogs.filter(l => l.port === 445).length / filteredLogs.length) * 100) : 0}%</div>
              </div>
              <div className="protocol-card">
                <div className="protocol-name">Other</div>
                <div className="protocol-value">{filteredLogs.filter(l => ![443, 80, 22, 3389, 21, 53, 445].includes(l.port)).length}</div>
                <div className="protocol-percentage">{filteredLogs.length > 0 ? Math.round((filteredLogs.filter(l => ![443, 80, 22, 3389, 21, 53, 445].includes(l.port)).length / filteredLogs.length) * 100) : 0}%</div>
              </div>
            </div>
          </div>
          
          {/* Geographic Threat Distribution */}
          <div className="stat-section full-width">
            <h3>🌍 Geographic Threat Distribution</h3>
            <div className="geo-threat-grid">
              {(() => {
                const countryCount = filteredLogs.reduce((acc, log) => {
                  const country = log.country || 'Unknown';
                  acc[country] = (acc[country] || 0) + 1;
                  return acc;
                }, {});
                const sortedCountries = Object.entries(countryCount)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 10);
                const maxCount = sortedCountries[0]?.[1] || 1;
                
                return sortedCountries.map(([country, count], index) => (
                  <div key={country} className="geo-threat-item">
                    <div className="geo-rank">#{index + 1}</div>
                    <div className="geo-flag">{country}</div>
                    <div className="geo-bar-container">
                      <div 
                        className="geo-bar" 
                        style={{ 
                          width: `${(count / maxCount) * 100}%`,
                          background: index < 3 ? '#dc2626' : index < 6 ? '#f59e0b' : '#3b82f6'
                        }}
                      />
                    </div>
                    <div className="geo-count">{count} threats</div>
                  </div>
                ));
              })()}
            </div>
          </div>
          
          {/* Attack Vector Intelligence */}
          <div className="charts-row">
            <div className="stat-section">
              <h3>🎯 Attack Vector Analysis</h3>
              <div className="vector-analysis">
                <div className="vector-item">
                  <div className="vector-header">
                    <Globe size={20} />
                    <span>Application Layer</span>
                  </div>
                  <div className="vector-stats">
                    <div className="vector-count">{filteredLogs.filter(l => 
                      ['SQL Injection', 'XSS', 'Command Injection', 'Path Traversal'].some(v => 
                        l.threatType?.includes(v.toLowerCase())
                      )
                    ).length}</div>
                    <div className="vector-risk high">HIGH RISK</div>
                  </div>
                  <div className="vector-bar">
                    <div style={{ width: '85%', background: '#dc2626' }} />
                  </div>
                </div>
                
                <div className="vector-item">
                  <div className="vector-header">
                    <Server size={20} />
                    <span>Network Layer</span>
                  </div>
                  <div className="vector-stats">
                    <div className="vector-count">{filteredLogs.filter(l => 
                      ['Port Scan', 'DDoS', 'SYN Flood'].some(v => 
                        l.threatType?.includes(v.toLowerCase())
                      )
                    ).length}</div>
                    <div className="vector-risk medium">MEDIUM RISK</div>
                  </div>
                  <div className="vector-bar">
                    <div style={{ width: '65%', background: '#f59e0b' }} />
                  </div>
                </div>
                
                <div className="vector-item">
                  <div className="vector-header">
                    <Lock size={20} />
                    <span>Authentication</span>
                  </div>
                  <div className="vector-stats">
                    <div className="vector-count">{filteredLogs.filter(l => 
                      ['Brute Force', 'Credential Stuffing'].some(v => 
                        l.threatType?.includes(v.toLowerCase())
                      )
                    ).length}</div>
                    <div className="vector-risk high">HIGH RISK</div>
                  </div>
                  <div className="vector-bar">
                    <div style={{ width: '75%', background: '#dc2626' }} />
                  </div>
                </div>
                
                <div className="vector-item">
                  <div className="vector-header">
                    <Database size={20} />
                    <span>Data Exfiltration</span>
                  </div>
                  <div className="vector-stats">
                    <div className="vector-count">{filteredLogs.filter(l => 
                      l.threatType?.includes('exfil')
                    ).length}</div>
                    <div className="vector-risk low">LOW RISK</div>
                  </div>
                  <div className="vector-bar">
                    <div style={{ width: '35%', background: '#3b82f6' }} />
                  </div>
                </div>
              </div>
            </div>
            
            <div className="stat-section">
              <h3>⏰ Hourly Activity Heatmap</h3>
              <div className="hourly-heatmap">
                {Array.from({ length: 24 }, (_, hour) => {
                  const hourLogs = filteredLogs.filter(l => {
                    const logHour = new Date(l.timestamp).getHours();
                    return logHour === hour;
                  });
                  const count = hourLogs.length;
                  const maxHourly = Math.max(...Array.from({ length: 24 }, (_, h) => 
                    filteredLogs.filter(l => new Date(l.timestamp).getHours() === h).length
                  ));
                  const intensity = maxHourly > 0 ? (count / maxHourly) : 0;
                  
                  return (
                    <div key={hour} className="heatmap-cell" title={`${hour}:00 - ${count} threats`}>
                      <div 
                        className="heatmap-block" 
                        style={{ 
                          background: intensity > 0.7 ? '#dc2626' : 
                                     intensity > 0.4 ? '#f59e0b' : 
                                     intensity > 0.2 ? '#3b82f6' : '#e5e7eb',
                          opacity: intensity > 0 ? 0.5 + (intensity * 0.5) : 0.3
                        }}
                      />
                      {hour % 4 === 0 && <div className="heatmap-label">{hour}h</div>}
                    </div>
                  );
                })}
              </div>
              <div className="heatmap-legend">
                <span>🟦 Low</span>
                <span>🟨 Medium</span>
                <span>🟥 High</span>
              </div>
            </div>
          </div>
          
          {/* Threat Intelligence Summary */}
          <div className="stat-section full-width threat-intel-summary">
            <h3>🧠 Threat Intelligence Summary</h3>
            <div className="intel-cards">
              <div className="intel-card">
                <div className="intel-icon">🎯</div>
                <div className="intel-content">
                  <div className="intel-title">Most Targeted Service</div>
                  <div className="intel-value">
                    {(() => {
                      const portCounts = {};
                      filteredLogs.forEach(l => {
                        portCounts[l.port] = (portCounts[l.port] || 0) + 1;
                      });
                      const topPort = Object.entries(portCounts).sort((a, b) => b[1] - a[1])[0];
                      const portNames = { 443: 'HTTPS', 80: 'HTTP', 22: 'SSH', 3389: 'RDP', 21: 'FTP', 53: 'DNS', 445: 'SMB' };
                      return topPort ? `${portNames[topPort[0]] || `Port ${topPort[0]}`} (${topPort[1]} attacks)` : 'N/A';
                    })()}
                  </div>
                </div>
              </div>
              
              <div className="intel-card">
                <div className="intel-icon">⚡</div>
                <div className="intel-content">
                  <div className="intel-title">Peak Attack Time</div>
                  <div className="intel-value">
                    {(() => {
                      const hourCounts = Array.from({ length: 24 }, (_, h) => ({
                        hour: h,
                        count: filteredLogs.filter(l => new Date(l.timestamp).getHours() === h).length
                      }));
                      const peak = hourCounts.sort((a, b) => b.count - a.count)[0];
                      return peak ? `${peak.hour}:00 - ${peak.hour + 1}:00 (${peak.count} threats)` : 'N/A';
                    })()}
                  </div>
                </div>
              </div>
              
              <div className="intel-card">
                <div className="intel-icon">🌍</div>
                <div className="intel-content">
                  <div className="intel-title">Primary Threat Origin</div>
                  <div className="intel-value">
                    {(() => {
                      const countryCounts = {};
                      filteredLogs.forEach(l => {
                        const country = l.country || 'Unknown';
                        countryCounts[country] = (countryCounts[country] || 0) + 1;
                      });
                      const topCountry = Object.entries(countryCounts).sort((a, b) => b[1] - a[1])[0];
                      return topCountry ? `${topCountry[0]} (${topCountry[1]} threats)` : 'N/A';
                    })()}
                  </div>
                </div>
              </div>
              
              <div className="intel-card">
                <div className="intel-icon">🛡️</div>
                <div className="intel-content">
                  <div className="intel-title">Defense Effectiveness</div>
                  <div className="intel-value">
                    {filteredLogs.length > 0 
                      ? `${Math.round((filteredLogs.filter(l => l.action === 'blocked').length / filteredLogs.length) * 100)}% blocked successfully`
                      : 'N/A'}
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          {/* Enhanced Timeline */}
          {statistics.timeline && statistics.timeline.length > 0 && (
            <div className="stat-section full-width">
              <h3>📈 Threat Activity Timeline (Last 30 Days)</h3>
              <div className="timeline-chart-enhanced">
                <div className="timeline-grid">
                  {statistics.timeline.slice(-30).map((point, index) => {
                    const maxCount = Math.max(...statistics.timeline.map(p => p.count));
                    const height = maxCount > 0 ? (point.count / maxCount) * 100 : 0;
                    return (
                      <div key={index} className="timeline-column">
                        <div className="timeline-bar-wrapper">
                          <div 
                            className="timeline-bar-enhanced" 
                            style={{ 
                              height: `${height}%`,
                              background: point.count > maxCount * 0.7 ? '#dc2626' : point.count > maxCount * 0.4 ? '#f59e0b' : '#3b82f6'
                            }}
                          >
                            <div className="timeline-tooltip-enhanced">
                              <strong>{new Date(point.date).toLocaleDateString()}</strong>
                              <div>{point.count} threats detected</div>
                            </div>
                          </div>
                        </div>
                        {index % 3 === 0 && <div className="timeline-label">{new Date(point.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</div>}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'forensics' && (
        <div className="forensics-content">
          {!selectedLog || !showForensics ? (
            <div className="forensics-overview">
              <div className="forensics-header">
                <h3>🔍 Forensic Analysis Center</h3>
                <p>Select a threat log below for detailed forensic analysis</p>
              </div>
              
              <div className="forensic-logs-list">
                {filteredLogs.length === 0 ? (
                  <div className="empty-state">
                    <Shield size={64} />
                    <p>No threat logs available for forensic analysis</p>
                  </div>
                ) : (
                  <table className="logs-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Source IP</th>
                        <th>Threat Type</th>
                        <th>Severity</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredLogs.slice(0, 50).map((log) => (
                        <tr key={log.id} onClick={() => handleViewForensics(log)} className="forensic-log-row">
                          <td>{new Date(log.timestamp).toLocaleString()}</td>
                          <td>
                            <div className="ip-cell">
                              <Globe size={14} />
                              {log.sourceIP}
                              {log.country && <span className="country-flag">{log.country}</span>}
                            </div>
                          </td>
                          <td>
                            <span className="threat-type">{log.threatType}</span>
                          </td>
                          <td>
                            <span className={`severity-badge ${log.severity}`}>
                              {getSeverityIcon(log.severity)} {log.severity.toUpperCase()}
                            </span>
                          </td>
                          <td>
                            <button 
                              className="btn-analyze"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleViewForensics(log);
                              }}
                            >
                              <Eye size={16} /> Analyze
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          ) : (
            <>
              <div className="forensics-header">
                <h3>🔍 Forensic Analysis</h3>
                <button onClick={() => {
                  setShowForensics(false);
                  setSelectedLog(null);
                  setForensicAnalysis(null);
                }} className="btn-close">
                  Back to List
                </button>
              </div>
              
              {forensicAnalysis ? (
            <div className="forensics-details">
              {/* Risk Score */}
              <div className="forensic-section">
                <h4>⚠️ Risk Assessment</h4>
                <div className="risk-score">
                  <div className="score-gauge">
                    <div className="score-value" style={{ 
                      width: `${forensicAnalysis.riskScore}%`,
                      background: forensicAnalysis.riskScore > 80 ? '#dc2626' : forensicAnalysis.riskScore > 50 ? '#f59e0b' : '#10b981'
                    }}></div>
                  </div>
                  <span className="score-label">{forensicAnalysis.riskScore}/100</span>
                </div>
              </div>
              
              {/* Attack Vector */}
              <div className="forensic-section">
                <h4>🎯 Attack Vector</h4>
                <div className="tags">
                  {forensicAnalysis.attackVector.map((vector, i) => (
                    <span key={i} className="tag">{vector}</span>
                  ))}
                </div>
              </div>
              
              {/* IOC Extraction */}
              <div className="forensic-section">
                <h4>🔍 Indicators of Compromise (IOCs)</h4>
                {forensicAnalysis.iocExtraction.ips.length > 0 && (
                  <div className="ioc-group">
                    <strong>IP Addresses:</strong>
                    <ul>
                      {forensicAnalysis.iocExtraction.ips.map((ip, i) => (
                        <li key={i}><code>{ip}</code></li>
                      ))}
                    </ul>
                  </div>
                )}
                {forensicAnalysis.iocExtraction.domains.length > 0 && (
                  <div className="ioc-group">
                    <strong>Domains:</strong>
                    <ul>
                      {forensicAnalysis.iocExtraction.domains.map((domain, i) => (
                        <li key={i}><code>{domain}</code></li>
                      ))}
                    </ul>
                  </div>
                )}
                {forensicAnalysis.iocExtraction.urls.length > 0 && (
                  <div className="ioc-group">
                    <strong>URLs:</strong>
                    <ul>
                      {forensicAnalysis.iocExtraction.urls.slice(0, 5).map((url, i) => (
                        <li key={i}><code>{url}</code></li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
              
              {/* MITRE ATT&CK Mapping */}
              {forensicAnalysis.mitreMapping.length > 0 && (
                <div className="forensic-section">
                  <h4>🎯 MITRE ATT&CK Techniques</h4>
                  <div className="mitre-techniques">
                    {forensicAnalysis.mitreMapping.map((technique, i) => (
                      <div key={i} className="mitre-technique">
                        <span className="technique-id">{technique.id}</span>
                        <span className="technique-name">{technique.name}</span>
                        <span className="technique-tactic">{technique.tactic}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              {/* Recommendations */}
              {forensicAnalysis.recommendations.length > 0 && (
                <div className="forensic-section">
                  <h4>💡 Recommended Actions</h4>
                  <div className="recommendations">
                    {forensicAnalysis.recommendations.map((rec, i) => (
                      <div key={i} className={`recommendation priority-${rec.priority}`}>
                        <Zap size={16} />
                        <div>
                          <strong>{rec.action}</strong>
                          <p>{rec.reason}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              {/* Network Analysis */}
              <div className="forensic-section">
                <h4>🌐 Network Analysis</h4>
                <div className="network-details">
                  <div className="detail-row">
                    <span>Source IP:</span>
                    <code>{forensicAnalysis.networkAnalysis.sourceInfo.ip}</code>
                  </div>
                  <div className="detail-row">
                    <span>IP Reputation:</span>
                    <span className={`reputation ${forensicAnalysis.networkAnalysis.sourceInfo.reputation}`}>
                      {forensicAnalysis.networkAnalysis.sourceInfo.reputation}
                    </span>
                  </div>
                  <div className="detail-row">
                    <span>Connection Type:</span>
                    <code>{forensicAnalysis.networkAnalysis.connectionMetrics.connectionType}</code>
                  </div>
                  <div className="detail-row">
                    <span>Packet Size:</span>
                    <code>{forensicAnalysis.networkAnalysis.connectionMetrics.packetSize} bytes</code>
                  </div>
                </div>
              </div>
              
              {/* Payload Analysis */}
              <div className="forensic-section">
                <h4>📦 Payload Analysis</h4>
                <div className="payload-details">
                  <div className="detail-row">
                    <span>Encoding:</span>
                    <code>{forensicAnalysis.payloadAnalysis.encoding}</code>
                  </div>
                  <div className="detail-row">
                    <span>Entropy:</span>
                    <code>{forensicAnalysis.payloadAnalysis.entropy}</code>
                  </div>
                  {forensicAnalysis.payloadAnalysis.suspiciousPatterns.length > 0 && (
                    <div className="detail-row">
                      <span>Suspicious Patterns:</span>
                      <div className="tags">
                        {forensicAnalysis.payloadAnalysis.suspiciousPatterns.map((pattern, i) => (
                          <span key={i} className="tag tag-danger">{pattern}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="loading-forensics">
              <Activity className="loading-spinner" size={32} />
              <p>Analyzing threat data...</p>
            </div>
          )}
            </>
          )}
        </div>
      )}

      {/* Export Modal */}
      <ExportModal
        isOpen={showExportModal}
        onClose={() => setShowExportModal(false)}
        onExport={handleExport}
        totalLogs={filteredLogs.length}
        filters={filters}
      />
    </div>
  );
};

export default FirewallLogs;
