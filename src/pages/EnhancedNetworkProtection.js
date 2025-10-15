import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Activity,
  AlertTriangle,
  Globe,
  Lock,
  Zap,
  TrendingUp,
  Eye,
  Ban,
  CheckCircle,
  XCircle,
  Clock,
  Server,
  Wifi,
  Radio,
  Target,
  Bell,
  BarChart3,
  PieChart,
  Network,
  X,
  AlertCircle,
  Info,
  Check
} from 'lucide-react';
import {
  getEnhancedConnections,
  getIDSStats,
  getDDoSStatus,
  setDDoSProtection,
  getTrafficAnalysis,
  getEnhancedNetworkStats,
  scanOpenPorts,
  getFirewallRules,
  addFirewallRule,
  updateFirewallRule,
  deleteFirewallRule,
  applySecurityProfile,
  blockIP
} from '../services/enhancedNetworkProtection';
import './EnhancedNetworkProtection.css';

const EnhancedNetworkProtection = () => {
  const [activeTab, setActiveTab] = useState('monitor');
  const [loading, setLoading] = useState(false);
  const [connections, setConnections] = useState(null);
  const [idsStats, setIDSStats] = useState(null);
  const [ddosStatus, setDDoSStatus] = useState(null);
  const [trafficAnalysis, setTrafficAnalysis] = useState(null);
  const [networkStats, setNetworkStats] = useState(null);
  const [firewallRules, setFirewallRules] = useState(null);
  const [openPorts, setOpenPorts] = useState([]);
  const [selectedConnection, setSelectedConnection] = useState(null);
  const [notification, setNotification] = useState(null);
  const [protectionLevel, setProtectionLevel] = useState('medium');

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const loadAllData = async () => {
    const [connData, idsData, ddosData, trafficData, statsData, rulesData] = await Promise.all([
      getEnhancedConnections(),
      getIDSStats(),
      getDDoSStatus(),
      getTrafficAnalysis(),
      getEnhancedNetworkStats(),
      getFirewallRules()
    ]);

    if (connData.success) setConnections(connData);
    if (idsData.success) setIDSStats(idsData);
    if (ddosData.success) setDDoSStatus(ddosData);
    if (trafficData.success) setTrafficAnalysis(trafficData);
    if (statsData.success) setNetworkStats(statsData);
    if (rulesData.success) setFirewallRules(rulesData);
  };

  const handleSetProtectionLevel = async (level) => {
    const result = await setDDoSProtection(level);
    if (result.success) {
      setProtectionLevel(level);
      showNotification(`DDoS protection set to ${level}`, 'success');
      await loadAllData();
    }
  };

  const handleBlockIP = async (ip, reason) => {
    const result = await blockIP(ip, reason);
    if (result.success) {
      showNotification(`IP ${ip} blocked successfully`, 'success');
      await loadAllData();
    }
  };

  const handleScanPorts = async () => {
    setLoading(true);
    const result = await scanOpenPorts();
    if (result.success) {
      setOpenPorts(result.ports);
      showNotification(`Found ${result.summary.total} open ports`, 'info');
    }
    setLoading(false);
  };

  const showNotification = (message, type = 'info') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 5000);
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const getThreatColor = (level) => {
    const colors = {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#3b82f6'
    };
    return colors[level] || '#64748b';
  };

  const getSeverityIcon = (level) => {
    switch (level) {
      case 'critical':
        return <XCircle className="severity-icon critical" />;
      case 'high':
        return <AlertTriangle className="severity-icon high" />;
      case 'medium':
        return <Bell className="severity-icon medium" />;
      default:
        return <CheckCircle className="severity-icon low" />;
    }
  };

  return (
    <div className="enhanced-network-protection">
      <div className="network-header">
        <div className="header-content">
          <div className="header-icon">
            <Shield size={32} />
          </div>
          <div className="header-text">
            <h1>Advanced Network Protection</h1>
            <p>Real-time intrusion detection, DDoS mitigation, and traffic analysis</p>
          </div>
        </div>

        {networkStats && (
          <div className="header-stats">
            <div className="stat-card">
              <Activity size={20} />
              <div>
                <div className="stat-value">{networkStats.stats.packetsAnalyzed.toLocaleString()}</div>
                <div className="stat-label">Packets Analyzed</div>
              </div>
            </div>
            <div className="stat-card stat-blocked">
              <Ban size={20} />
              <div>
                <div className="stat-value">{networkStats.stats.packetsBlocked.toLocaleString()}</div>
                <div className="stat-label">Threats Blocked</div>
              </div>
            </div>
            <div className="stat-card stat-suspicious">
              <AlertTriangle size={20} />
              <div>
                <div className="stat-value">{networkStats.stats.suspiciousPackets.toLocaleString()}</div>
                <div className="stat-label">Suspicious</div>
              </div>
            </div>
            <div className="stat-card stat-bandwidth">
              <TrendingUp size={20} />
              <div>
                <div className="stat-value">{networkStats.stats.bandwidth.current.toFixed(1)} Mbps</div>
                <div className="stat-label">Bandwidth</div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="network-tabs">
        {[
          { id: 'monitor', label: 'Live Monitor', icon: Activity },
          { id: 'ids', label: 'Intrusion Detection', icon: Eye },
          { id: 'ddos', label: 'DDoS Protection', icon: Shield },
          { id: 'traffic', label: 'Traffic Analysis', icon: BarChart3 },
          { id: 'firewall', label: 'Firewall', icon: Lock },
          { id: 'ports', label: 'Port Scan', icon: Server }
        ].map(tab => (
          <button
            key={tab.id}
            className={`tab-button ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <tab.icon size={18} />
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        {notification && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className={`notification notification-${notification.type}`}
          >
            <Bell size={16} />
            <span>{notification.message}</span>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="network-content">
        <AnimatePresence mode="wait">
          {/* Live Monitor Tab */}
          {activeTab === 'monitor' && connections && (
            <motion.div
              key="monitor"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="tab-content"
            >
              {connections.summary.threats > 0 && (
                <div className="alert alert-critical">
                  <AlertTriangle size={24} />
                  <div>
                    <h4>⚠️ {connections.summary.critical} Critical & {connections.summary.high} High Threats Detected</h4>
                    <p>Immediate action required. Review connections below and block suspicious IPs.</p>
                  </div>
                </div>
              )}

              <div className="connections-summary">
                <div className="summary-card">
                  <Network size={24} />
                  <div>
                    <div className="summary-value">{connections.summary.total}</div>
                    <div className="summary-label">Total Connections</div>
                  </div>
                </div>
                <div className="summary-card">
                  <CheckCircle size={24} />
                  <div>
                    <div className="summary-value">{connections.summary.established}</div>
                    <div className="summary-label">Established</div>
                  </div>
                </div>
                <div className="summary-card">
                  <TrendingUp size={24} />
                  <div>
                    <div className="summary-value">{connections.summary.outbound}</div>
                    <div className="summary-label">Outbound</div>
                  </div>
                </div>
                <div className="summary-card summary-threats">
                  <XCircle size={24} />
                  <div>
                    <div className="summary-value">{connections.summary.threats}</div>
                    <div className="summary-label">Threats</div>
                  </div>
                </div>
              </div>

              <div className="connections-table">
                <h3>
                  <Eye size={20} />
                  Active Connections
                </h3>
                
                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Status</th>
                        <th>Process</th>
                        <th>Protocol</th>
                        <th>Remote Address</th>
                        <th>Location</th>
                        <th>Traffic</th>
                        <th>Latency</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {connections.connections.map(conn => (
                        <tr 
                          key={conn.id}
                          className={conn.threat ? `threat-row threat-${conn.threat.level}` : ''}
                          onClick={() => setSelectedConnection(conn)}
                        >
                          <td>
                            {conn.threat ? (
                              <div className="threat-badge" style={{ borderLeftColor: getThreatColor(conn.threat.level) }}>
                                {getSeverityIcon(conn.threat.level)}
                                <span className="threat-type">{conn.threat.type}</span>
                              </div>
                            ) : (
                              <div className="status-badge status-safe">
                                <CheckCircle size={16} />
                                <span>{conn.state}</span>
                              </div>
                            )}
                          </td>
                          <td>
                            <div className="process-info">
                              <span className="process-name">{conn.process}</span>
                              <span className="process-pid">PID: {conn.pid}</span>
                            </div>
                          </td>
                          <td>
                            <span className={`protocol-badge protocol-${conn.protocol.toLowerCase()}`}>
                              {conn.protocol}
                            </span>
                          </td>
                          <td>
                            <div className="address-info">
                              <span className="address">{conn.remoteAddress}:{conn.remotePort}</span>
                            </div>
                          </td>
                          <td>
                            {conn.geo && (
                              <div className="geo-info">
                                <span className="geo-flag">{conn.geo.flag}</span>
                                <div>
                                  <div className="geo-country">{conn.geo.country}</div>
                                  <div className="geo-org">{conn.geo.org}</div>
                                </div>
                              </div>
                            )}
                          </td>
                          <td>
                            <div className="bandwidth-info">
                              <div className="bandwidth-sent">↑ {formatBytes(conn.bandwidth.sent)}</div>
                              <div className="bandwidth-received">↓ {formatBytes(conn.bandwidth.received)}</div>
                            </div>
                          </td>
                          <td>
                            <span className={`latency ${conn.latency > 100 ? 'high' : 'normal'}`}>
                              {conn.latency}ms
                            </span>
                          </td>
                          <td>
                            {conn.threat && conn.remoteAddress !== '*' && (
                              <button
                                className="action-button action-block"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleBlockIP(conn.remoteAddress, conn.threat.description);
                                }}
                              >
                                <Ban size={14} />
                                Block
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {selectedConnection && (
                <div className="connection-details-modal" onClick={() => setSelectedConnection(null)}>
                  <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                    <div className="modal-header">
                      <h3>Connection Details</h3>
                      <button className="close-button" onClick={() => setSelectedConnection(null)}>×</button>
                    </div>
                    <div className="modal-body">
                      <div className="detail-grid">
                        <div className="detail-item">
                          <label>Process</label>
                          <span>{selectedConnection.process} (PID: {selectedConnection.pid})</span>
                        </div>
                        <div className="detail-item">
                          <label>Protocol</label>
                          <span>{selectedConnection.protocol}</span>
                        </div>
                        <div className="detail-item">
                          <label>Local Address</label>
                          <span>{selectedConnection.localAddress}:{selectedConnection.localPort}</span>
                        </div>
                        <div className="detail-item">
                          <label>Remote Address</label>
                          <span>{selectedConnection.remoteAddress}:{selectedConnection.remotePort}</span>
                        </div>
                        <div className="detail-item">
                          <label>State</label>
                          <span>{selectedConnection.state}</span>
                        </div>
                        <div className="detail-item">
                          <label>Duration</label>
                          <span>{selectedConnection.duration}s</span>
                        </div>
                        <div className="detail-item">
                          <label>Packets Sent</label>
                          <span>{selectedConnection.packets?.sent || 0}</span>
                        </div>
                        <div className="detail-item">
                          <label>Packets Received</label>
                          <span>{selectedConnection.packets?.received || 0}</span>
                        </div>
                      </div>

                      {selectedConnection.threat && (
                        <div className="threat-details">
                          <h4>
                            <AlertTriangle size={20} />
                            Threat Information
                          </h4>
                          <div className="threat-info">
                            <div><strong>Type:</strong> {selectedConnection.threat.type}</div>
                            <div><strong>Severity:</strong> <span style={{ color: getThreatColor(selectedConnection.threat.level) }}>{selectedConnection.threat.level.toUpperCase()}</span></div>
                            <div><strong>Description:</strong> {selectedConnection.threat.description}</div>
                          </div>
                        </div>
                      )}

                      {selectedConnection.idsAnalysis && selectedConnection.idsAnalysis.length > 0 && (
                        <div className="ids-analysis">
                          <h4>
                            <Eye size={20} />
                            IDS Analysis
                          </h4>
                          {selectedConnection.idsAnalysis.map((threat, idx) => (
                            <div key={idx} className="analysis-item">
                              <div><strong>{threat.type}</strong></div>
                              <div>{threat.description}</div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {/* IDS Tab */}
          {activeTab === 'ids' && idsStats && (
            <motion.div
              key="ids"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="tab-content"
            >
              <div className="ids-overview">
                <h3>
                  <Eye size={20} />
                  Intrusion Detection System Status
                </h3>

                <div className="ids-stats-grid">
                  <div className="stat-box">
                    <div className="stat-icon">
                      <Activity size={24} />
                    </div>
                    <div className="stat-content">
                      <div className="stat-number">{idsStats.stats.analyzed.toLocaleString()}</div>
                      <div className="stat-desc">Packets Analyzed</div>
                    </div>
                  </div>

                  <div className="stat-box stat-blocked">
                    <div className="stat-icon">
                      <Ban size={24} />
                    </div>
                    <div className="stat-content">
                      <div className="stat-number">{idsStats.stats.blocked.toLocaleString()}</div>
                      <div className="stat-desc">Packets Blocked</div>
                    </div>
                  </div>

                  <div className="stat-box stat-suspicious">
                    <div className="stat-icon">
                      <AlertTriangle size={24} />
                    </div>
                    <div className="stat-content">
                      <div className="stat-number">{idsStats.stats.suspicious.toLocaleString()}</div>
                      <div className="stat-desc">Suspicious Packets</div>
                    </div>
                  </div>

                  <div className="stat-box">
                    <div className="stat-icon">
                      <Target size={24} />
                    </div>
                    <div className="stat-content">
                      <div className="stat-number">{idsStats.stats.recentThreats}</div>
                      <div className="stat-desc">Recent Threats</div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="attack-signatures">
                <h3>
                  <Target size={20} />
                  Active Attack Signatures
                </h3>

                <div className="signatures-grid">
                  {idsStats.signatures.map(sig => (
                    <div key={sig.id} className={`signature-card signature-${sig.severity}`}>
                      <div className="signature-header">
                        <h4>{sig.name}</h4>
                        <span className={`severity-badge severity-${sig.severity}`}>
                          {sig.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="signature-desc">{sig.description}</p>
                      <div className="signature-meta">
                        <div><strong>Pattern:</strong> {sig.pattern}</div>
                        <div><strong>Threshold:</strong> {sig.threshold} events in {sig.timeWindow}s</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="recent-threats">
                <h3>
                  <Clock size={20} />
                  Recent Threat Activity
                </h3>

                <div className="threats-list">
                  {idsStats.recentThreats.slice(0, 10).map((threat, idx) => (
                    <div key={idx} className="threat-item">
                      <div className="threat-time">
                        {new Date(threat.timestamp).toLocaleTimeString()}
                      </div>
                      <div className="threat-content">
                        {threat.threats.map((t, ti) => (
                          <div key={ti} className="threat-entry">
                            {getSeverityIcon(t.severity)}
                            <div>
                              <strong>{t.type}</strong>
                              <p>{t.description}</p>
                              {t.ip && <span className="threat-ip">IP: {t.ip}</span>}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          )}

          {/* DDoS Protection Tab */}
          {activeTab === 'ddos' && ddosStatus && (
            <motion.div
              key="ddos"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="tab-content"
            >
              <div className="ddos-header">
                <h3>
                  <Shield size={20} />
                  DDoS Protection Configuration
                </h3>

                <div className="protection-level-selector">
                  {['low', 'medium', 'high', 'maximum'].map(level => (
                    <button
                      key={level}
                      className={`level-button ${protectionLevel === level ? 'active' : ''}`}
                      onClick={() => handleSetProtectionLevel(level)}
                    >
                      {level === 'low' && <Zap size={16} />}
                      {level === 'medium' && <Shield size={16} />}
                      {level === 'high' && <Lock size={16} />}
                      {level === 'maximum' && <Ban size={16} />}
                      {level.charAt(0).toUpperCase() + level.slice(1)}
                    </button>
                  ))}
                </div>
              </div>

              <div className="ddos-stats">
                <div className="ddos-stat-card">
                  <h4>Protection Level</h4>
                  <div className="stat-value-large">{ddosStatus.stats.protectionLevel.toUpperCase()}</div>
                </div>

                <div className="ddos-stat-card">
                  <h4>Max Connections/IP</h4>
                  <div className="stat-value-large">{ddosStatus.stats.rateLimit.maxConnectionsPerIP}</div>
                </div>

                <div className="ddos-stat-card">
                  <h4>Max Packets/Second</h4>
                  <div className="stat-value-large">{ddosStatus.stats.rateLimit.maxPacketsPerSecond}</div>
                </div>

                <div className="ddos-stat-card stat-mitigations">
                  <h4>Total Mitigations</h4>
                  <div className="stat-value-large">{ddosStatus.stats.totalMitigations}</div>
                </div>
              </div>

              <div className="mitigation-history">
                <h3>
                  <Clock size={20} />
                  Mitigation History
                </h3>

                {ddosStatus.mitigationHistory.length === 0 ? (
                  <div className="empty-state">
                    <CheckCircle size={48} />
                    <h4>No DDoS Attacks Detected</h4>
                    <p>Your network is currently safe from DDoS attacks</p>
                  </div>
                ) : (
                  <div className="mitigations-table">
                    <table>
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Source IP</th>
                          <th>Attack Type</th>
                          <th>Severity</th>
                          <th>Metric</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ddosStatus.mitigationHistory.map((mitigation, idx) => (
                          <tr key={idx}>
                            <td>{new Date(mitigation.timestamp).toLocaleString()}</td>
                            <td><code>{mitigation.ip}</code></td>
                            <td>{mitigation.attackType}</td>
                            <td>
                              <span className={`severity-badge severity-${mitigation.severity}`}>
                                {mitigation.severity.toUpperCase()}
                              </span>
                            </td>
                            <td>{mitigation.metric}</td>
                            <td>
                              <span className="action-badge action-blocked">
                                {mitigation.action}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* Traffic Analysis Tab */}
          {activeTab === 'traffic' && trafficAnalysis && (
            <motion.div
              key="traffic"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="tab-content"
            >
              <div className="traffic-overview">
                <h3>
                  <BarChart3 size={20} />
                  Traffic Overview
                </h3>

                <div className="traffic-metrics">
                  <div className="metric-card">
                    <div className="metric-header">
                      <span>Current Bandwidth</span>
                      <TrendingUp size={18} />
                    </div>
                    <div className="metric-value">{trafficAnalysis.bandwidthTrend.current.toFixed(2)} Mbps</div>
                    <div className="metric-subtitle">{trafficAnalysis.bandwidthTrend.packetCount} packets/min</div>
                  </div>

                  <div className="metric-card">
                    <div className="metric-header">
                      <span>Total Traffic</span>
                      <Activity size={18} />
                    </div>
                    <div className="metric-value">{formatBytes(trafficAnalysis.bandwidthTrend.totalBytes)}</div>
                    <div className="metric-subtitle">Last 60 seconds</div>
                  </div>
                </div>
              </div>

              <div className="protocol-distribution">
                <h3>
                  <PieChart size={20} />
                  Protocol Distribution
                </h3>

                <div className="protocols-grid">
                  {Object.entries(trafficAnalysis.protocolDistribution).map(([protocol, stats]) => (
                    <div key={protocol} className="protocol-stat">
                      <div className="protocol-name">{protocol}</div>
                      <div className="protocol-packets">{stats.packets.toLocaleString()} packets</div>
                      <div className="protocol-bytes">{formatBytes(stats.bytes)}</div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="traffic-tables">
                <div className="top-ports">
                  <h3>
                    <Server size={20} />
                    Top Ports by Traffic
                  </h3>

                  <table>
                    <thead>
                      <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Packets</th>
                        <th>Data</th>
                      </tr>
                    </thead>
                    <tbody>
                      {trafficAnalysis.topPorts.map(port => (
                        <tr key={port.port}>
                          <td><code>{port.port}</code></td>
                          <td>{port.service}</td>
                          <td>{port.packets.toLocaleString()}</td>
                          <td>{formatBytes(port.bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="top-countries">
                  <h3>
                    <Globe size={20} />
                    Top Countries by Traffic
                  </h3>

                  <table>
                    <thead>
                      <tr>
                        <th>Country</th>
                        <th>Packets</th>
                        <th>Data</th>
                      </tr>
                    </thead>
                    <tbody>
                      {trafficAnalysis.topCountries.map(country => (
                        <tr key={country.country}>
                          <td>
                            <span className="country-name">
                              {country.flag} {country.country}
                            </span>
                          </td>
                          <td>{country.packets.toLocaleString()}</td>
                          <td>{formatBytes(country.bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </motion.div>
          )}

          {/* Firewall Tab */}
          {activeTab === 'firewall' && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="firewall-tab"
            >
              <div className="firewall-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
                <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', margin: 0 }}>
                  <Shield size={24} /> Firewall Rules
                </h3>
                <button 
                  className="action-button action-add"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    padding: '0.75rem 1.25rem',
                    background: 'rgba(34, 197, 94, 0.2)',
                    border: '1px solid rgba(34, 197, 94, 0.4)',
                    borderRadius: '8px',
                    color: '#4ade80',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                  onClick={() => showNotification('Feature coming soon', 'info')}
                >
                  <Lock size={18} />
                  Add Rule
                </button>
              </div>

              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Direction</th>
                      <th>Action</th>
                      <th>Protocol</th>
                      <th>Remote Address</th>
                      <th>Port</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {firewallRules && firewallRules.map((rule) => (
                      <tr key={rule.id}>
                        <td className="rule-name" style={{ fontWeight: 600 }}>{rule.name}</td>
                        <td>
                          <span 
                            className={`direction-badge direction-${rule.direction}`}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.4rem',
                              padding: '0.4rem 0.75rem',
                              borderRadius: '6px',
                              fontSize: '0.85rem',
                              background: rule.direction === 'inbound' ? 'rgba(59, 130, 246, 0.2)' : 'rgba(168, 85, 247, 0.2)',
                              color: rule.direction === 'inbound' ? '#60a5fa' : '#a78bfa',
                              border: `1px solid ${rule.direction === 'inbound' ? 'rgba(59, 130, 246, 0.4)' : 'rgba(168, 85, 247, 0.4)'}`
                            }}
                          >
                            {rule.direction === 'inbound' ? '↓' : '↑'}
                            {rule.direction}
                          </span>
                        </td>
                        <td>
                          <span 
                            className={`action-type action-${rule.action}`}
                            style={{
                              padding: '0.4rem 0.75rem',
                              borderRadius: '6px',
                              fontSize: '0.85rem',
                              fontWeight: 600,
                              background: rule.action === 'allow' ? 'rgba(34, 197, 94, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                              color: rule.action === 'allow' ? '#4ade80' : '#ef4444',
                              border: `1px solid ${rule.action === 'allow' ? 'rgba(34, 197, 94, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`
                            }}
                          >
                            {rule.action.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <span className={`protocol-badge protocol-${rule.protocol.toLowerCase()}`}>
                            {rule.protocol}
                          </span>
                        </td>
                        <td><code>{rule.remoteAddress}</code></td>
                        <td><code>{rule.port}</code></td>
                        <td>
                          <span 
                            className={`status-toggle ${rule.enabled ? 'enabled' : 'disabled'}`}
                            style={{
                              padding: '0.4rem 0.75rem',
                              borderRadius: '6px',
                              fontSize: '0.85rem',
                              background: rule.enabled ? 'rgba(34, 197, 94, 0.1)' : 'rgba(100, 116, 139, 0.1)',
                              color: rule.enabled ? '#4ade80' : '#94a3b8',
                              border: `1px solid ${rule.enabled ? 'rgba(34, 197, 94, 0.3)' : 'rgba(100, 116, 139, 0.3)'}`
                            }}
                          >
                            {rule.enabled ? 'Enabled' : 'Disabled'}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '0.5rem' }}>
                            <button 
                              className="icon-button"
                              style={{
                                background: 'rgba(59, 130, 246, 0.2)',
                                border: '1px solid rgba(59, 130, 246, 0.4)',
                                borderRadius: '6px',
                                color: '#60a5fa',
                                padding: '0.4rem',
                                cursor: 'pointer',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center'
                              }}
                              onClick={() => showNotification('Feature coming soon', 'info')}
                              title="Edit rule"
                            >
                              <Lock size={16} />
                            </button>
                            <button 
                              className="icon-button delete"
                              style={{
                                background: 'rgba(239, 68, 68, 0.2)',
                                border: '1px solid rgba(239, 68, 68, 0.4)',
                                borderRadius: '6px',
                                color: '#ef4444',
                                padding: '0.4rem',
                                cursor: 'pointer',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center'
                              }}
                              onClick={() => showNotification('Feature coming soon', 'info')}
                              title="Delete rule"
                            >
                              <X size={16} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}

          {/* Port Scan Tab */}
          {activeTab === 'ports' && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="port-scan-tab"
            >
              <div className="scan-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
                <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', margin: 0 }}>
                  <Network size={24} /> Port Scanner
                </h3>
                <button 
                  className="action-button action-scan"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    padding: '0.75rem 1.25rem',
                    background: 'rgba(59, 130, 246, 0.2)',
                    border: '1px solid rgba(59, 130, 246, 0.4)',
                    borderRadius: '8px',
                    color: '#60a5fa',
                    fontWeight: 600,
                    cursor: loading ? 'not-allowed' : 'pointer',
                    opacity: loading ? 0.6 : 1
                  }}
                  onClick={async () => {
                    setLoading(true);
                    showNotification('Scanning ports...', 'info');
                    try {
                      const result = await scanOpenPorts();
                      if (result.success) {
                        setOpenPorts(result.ports);
                        showNotification(`Scan complete - Found ${result.summary.total} open ports`, 'success');
                      } else {
                        showNotification('Scan failed', 'error');
                      }
                    } catch (error) {
                      showNotification('Scan failed', 'error');
                    } finally {
                      setLoading(false);
                    }
                  }}
                  disabled={loading}
                >
                  {loading ? <Activity size={18} className="spinning" /> : <Target size={18} />}
                  {loading ? 'Scanning...' : 'Scan Ports'}
                </button>
              </div>

              {!openPorts || openPorts.length === 0 ? (
                <div className="empty-state">
                  <Network size={64} />
                  <h4>No Scan Results</h4>
                  <p>Click "Scan Ports" to start scanning for open ports</p>
                </div>
              ) : (
                <>
                  <div className="port-summary" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
                    <div className="summary-card">
                      <Globe size={32} />
                      <div>
                        <div className="summary-value">{openPorts.length}</div>
                        <div className="summary-label">Total Ports</div>
                      </div>
                    </div>
                    <div className="summary-card summary-threats">
                      <AlertTriangle size={32} />
                      <div>
                        <div className="summary-value">
                          {openPorts.filter(p => p.risk === 'high' || p.risk === 'critical').length}
                        </div>
                        <div className="summary-label">High Risk</div>
                      </div>
                    </div>
                    <div className="summary-card summary-suspicious">
                      <Activity size={32} />
                      <div>
                        <div className="summary-value">
                          {openPorts.filter(p => p.state === 'listening').length}
                        </div>
                        <div className="summary-label">Listening</div>
                      </div>
                    </div>
                  </div>

                  <div className="table-container">
                    <table>
                      <thead>
                        <tr>
                          <th>Port</th>
                          <th>Protocol</th>
                          <th>Service</th>
                          <th>State</th>
                          <th>Process</th>
                          <th>Risk Level</th>
                          <th>Recommendation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {openPorts.map((port, index) => (
                          <tr 
                            key={index}
                            className={port.risk === 'high' || port.risk === 'critical' ? 'threat-row' : ''}
                          >
                            <td>
                              <code className="port-number" style={{ fontWeight: 700 }}>{port.port}</code>
                            </td>
                            <td>
                              <span className={`protocol-badge protocol-${port.protocol.toLowerCase()}`}>
                                {port.protocol}
                              </span>
                            </td>
                            <td className="service-name" style={{ fontWeight: 500 }}>{port.service}</td>
                            <td>
                              <span 
                                className={`state-badge state-${port.state}`}
                                style={{
                                  padding: '0.4rem 0.75rem',
                                  borderRadius: '6px',
                                  fontSize: '0.85rem',
                                  background: port.state === 'listening' ? 'rgba(34, 197, 94, 0.2)' : 'rgba(100, 116, 139, 0.2)',
                                  color: port.state === 'listening' ? '#4ade80' : '#94a3b8',
                                  border: `1px solid ${port.state === 'listening' ? 'rgba(34, 197, 94, 0.4)' : 'rgba(100, 116, 139, 0.4)'}`
                                }}
                              >
                                {port.state}
                              </span>
                            </td>
                            <td className="process-info">
                              <div className="process-name">{port.process}</div>
                              <div className="process-pid">PID: {port.pid}</div>
                            </td>
                            <td>
                              <span 
                                className={`risk-badge risk-${port.risk}`}
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '0.4rem',
                                  padding: '0.4rem 0.75rem',
                                  borderRadius: '6px',
                                  fontSize: '0.85rem',
                                  fontWeight: 600,
                                  textTransform: 'uppercase',
                                  background: port.risk === 'critical' ? 'rgba(239, 68, 68, 0.2)' :
                                             port.risk === 'high' ? 'rgba(251, 146, 60, 0.2)' :
                                             port.risk === 'medium' ? 'rgba(234, 179, 8, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                                  color: port.risk === 'critical' ? '#ef4444' :
                                         port.risk === 'high' ? '#fb923c' :
                                         port.risk === 'medium' ? '#eab308' : '#60a5fa',
                                  border: `1px solid ${port.risk === 'critical' ? 'rgba(239, 68, 68, 0.4)' :
                                                        port.risk === 'high' ? 'rgba(251, 146, 60, 0.4)' :
                                                        port.risk === 'medium' ? 'rgba(234, 179, 8, 0.4)' : 'rgba(59, 130, 246, 0.4)'}`
                                }}
                              >
                                {port.risk === 'critical' && <AlertCircle size={16} />}
                                {port.risk === 'high' && <AlertTriangle size={16} />}
                                {port.risk === 'medium' && <AlertCircle size={16} />}
                                {port.risk === 'low' && <CheckCircle size={16} />}
                                {port.risk}
                              </span>
                            </td>
                            <td className="recommendation" style={{ color: '#cbd5e1', fontSize: '0.9rem' }}>
                              {port.recommendation}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};

export default EnhancedNetworkProtection;
