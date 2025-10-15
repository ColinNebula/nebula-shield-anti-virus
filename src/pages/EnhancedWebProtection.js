import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Globe, AlertTriangle, CheckCircle, X, Lock, Unlock, TrendingUp,
  Activity, Database, Eye, EyeOff, Settings, Download, Upload, Trash2,
  Plus, Search, Filter, Clock, Ban, Check, Info, Zap, BarChart3
} from 'lucide-react';
import enhancedWebProtection from '../services/enhancedWebProtection';
import { toast } from 'react-hot-toast';
import './EnhancedWebProtection.css';

function EnhancedWebProtection() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [statistics, setStatistics] = useState(null);
  const [settings, setSettings] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [blockedDomains, setBlockedDomains] = useState([]);
  const [allowedDomains, setAllowedDomains] = useState([]);
  
  const [newBlockedDomain, setNewBlockedDomain] = useState('');
  const [newAllowedDomain, setNewAllowedDomain] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('all');

  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = useCallback(() => {
    setStatistics(enhancedWebProtection.getStatistics());
    setSettings(enhancedWebProtection.getSettings());
    setScanHistory(enhancedWebProtection.getScanHistory());
    setBlockedDomains(enhancedWebProtection.getBlockedDomains());
    setAllowedDomains(enhancedWebProtection.getAllowedDomains());
  }, []);

  const handleScanURL = async () => {
    if (!url.trim()) {
      toast.error('Please enter a URL to scan');
      return;
    }

    // Validate URL format
    try {
      new URL(url.startsWith('http') ? url : `https://${url}`);
    } catch {
      toast.error('Invalid URL format');
      return;
    }

    setScanning(true);
    setScanResult(null);

    try {
      const fullURL = url.startsWith('http') ? url : `https://${url}`;
      const result = await enhancedWebProtection.scanURL(fullURL);
      setScanResult(result);
      loadAllData();

      if (result.safe) {
        toast.success('✅ URL is safe!');
      } else {
        toast.error(`⚠️ ${result.threats.length} threat(s) detected!`);
      }
    } catch (error) {
      toast.error('Scan failed: ' + error.message);
    } finally {
      setScanning(false);
    }
  };

  const handleToggleSetting = (setting, value) => {
    switch (setting) {
      case 'enabled':
        enhancedWebProtection.setEnabled(value);
        toast.success(value ? 'Web Protection Enabled' : 'Web Protection Disabled');
        break;
      case 'realTimeProtection':
        enhancedWebProtection.setRealTimeProtection(value);
        toast.success(value ? 'Real-Time Protection Enabled' : 'Real-Time Protection Disabled');
        break;
      case 'blockPhishing':
        enhancedWebProtection.setBlockPhishing(value);
        toast.success(value ? 'Phishing Blocking Enabled' : 'Phishing Blocking Disabled');
        break;
      case 'blockMalware':
        enhancedWebProtection.setBlockMalware(value);
        toast.success(value ? 'Malware Blocking Enabled' : 'Malware Blocking Disabled');
        break;
      case 'requireHTTPS':
        enhancedWebProtection.setRequireHTTPS(value);
        toast.success(value ? 'HTTPS Required' : 'HTTPS Optional');
        break;
      default:
        break;
    }
    loadAllData();
  };

  const handleBlockDomain = () => {
    if (!newBlockedDomain.trim()) {
      toast.error('Please enter a domain to block');
      return;
    }

    enhancedWebProtection.blockDomain(newBlockedDomain.toLowerCase(), 'User blocked');
    toast.success(`Blocked domain: ${newBlockedDomain}`);
    setNewBlockedDomain('');
    loadAllData();
  };

  const handleUnblockDomain = (domain) => {
    enhancedWebProtection.unblockDomain(domain);
    toast.success(`Unblocked domain: ${domain}`);
    loadAllData();
  };

  const handleAddToAllowlist = () => {
    if (!newAllowedDomain.trim()) {
      toast.error('Please enter a domain to allow');
      return;
    }

    enhancedWebProtection.addToAllowlist(newAllowedDomain.toLowerCase());
    toast.success(`Added to allowlist: ${newAllowedDomain}`);
    setNewAllowedDomain('');
    loadAllData();
  };

  const handleRemoveFromAllowlist = (domain) => {
    enhancedWebProtection.removeFromAllowlist(domain);
    toast.success(`Removed from allowlist: ${domain}`);
    loadAllData();
  };

  const handleClearHistory = () => {
    if (window.confirm('Are you sure you want to clear scan history?')) {
      enhancedWebProtection.clearScanHistory();
      toast.success('Scan history cleared');
      loadAllData();
    }
  };

  const handleResetStatistics = () => {
    if (window.confirm('Are you sure you want to reset statistics?')) {
      enhancedWebProtection.resetStatistics();
      toast.success('Statistics reset');
      loadAllData();
    }
  };

  const handleExportSettings = () => {
    const data = enhancedWebProtection.exportSettings();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `web-protection-settings-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Settings exported');
  };

  const handleImportSettings = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target.result);
        const result = enhancedWebProtection.importSettings(data);
        if (result.success) {
          toast.success('Settings imported successfully');
          loadAllData();
        } else {
          toast.error('Import failed: ' + result.error);
        }
      } catch (error) {
        toast.error('Invalid settings file');
      }
    };
    reader.readAsText(file);
  };

  const getRiskColor = (score) => {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#ef4444',
      high: '#fb923c',
      medium: '#eab308',
      low: '#60a5fa'
    };
    return colors[severity] || '#94a3b8';
  };

  const filteredHistory = scanHistory.filter(scan => {
    if (searchQuery && !scan.url.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    if (filterType === 'safe' && !scan.safe) return false;
    if (filterType === 'threats' && scan.safe) return false;
    return true;
  });

  return (
    <div className="enhanced-web-protection">
      {/* Header */}
      <motion.div
        className="protection-header"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="header-content">
          <div className="header-icon">
            <Shield size={48} />
          </div>
          <div className="header-text">
            <h1>
              <Globe size={28} />
              Enhanced Web Protection
            </h1>
            <p>Real-time threat detection, phishing protection, and malicious URL blocking</p>
          </div>
        </div>
        <div className="protection-status">
          {settings && (
            <div className="status-indicator">
              <div className={`status-dot ${settings.enabled ? 'active' : ''}`} />
              <span>{settings.enabled ? 'Protected' : 'Disabled'}</span>
            </div>
          )}
        </div>
      </motion.div>

      {/* Statistics Cards */}
      {statistics && (
        <motion.div
          className="stats-grid"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
        >
          <motion.div className="stat-card" whileHover={{ scale: 1.02 }}>
            <div className="stat-icon">
              <TrendingUp size={32} />
            </div>
            <div className="stat-value">{statistics.totalScans}</div>
            <div className="stat-label">Total Scans</div>
          </motion.div>

          <motion.div className="stat-card danger" whileHover={{ scale: 1.02 }}>
            <div className="stat-icon danger">
              <AlertTriangle size={32} />
            </div>
            <div className="stat-value">{statistics.threatsBlocked}</div>
            <div className="stat-label">Threats Blocked</div>
          </motion.div>

          <motion.div className="stat-card warning" whileHover={{ scale: 1.02 }}>
            <div className="stat-icon warning">
              <Ban size={32} />
            </div>
            <div className="stat-value">{statistics.phishingBlocked}</div>
            <div className="stat-label">Phishing Blocked</div>
          </motion.div>

          <motion.div className="stat-card success" whileHover={{ scale: 1.02 }}>
            <div className="stat-icon success">
              <CheckCircle size={32} />
            </div>
            <div className="stat-value">{statistics.urlsAllowed}</div>
            <div className="stat-label">URLs Allowed</div>
          </motion.div>
        </motion.div>
      )}

      {/* Tabs */}
      <div className="protection-tabs">
        {['scanner', 'blocklist', 'allowlist', 'history', 'settings'].map((tab) => (
          <button
            key={tab}
            className={`tab-button ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab === 'scanner' && <Zap size={18} />}
            {tab === 'blocklist' && <Ban size={18} />}
            {tab === 'allowlist' && <Check size={18} />}
            {tab === 'history' && <Clock size={18} />}
            {tab === 'settings' && <Settings size={18} />}
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          className="tab-content"
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -20 }}
          transition={{ duration: 0.3 }}
        >
          {/* SCANNER TAB */}
          {activeTab === 'scanner' && (
            <div className="scanner-section">
              <div className="scan-controls">
                <h3>
                  <Globe size={20} />
                  URL Scanner
                </h3>
                <div className="url-input-group">
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="Enter URL to scan (e.g., https://example.com)"
                    disabled={scanning || !settings?.enabled}
                    onKeyPress={(e) => e.key === 'Enter' && handleScanURL()}
                  />
                  <button
                    onClick={handleScanURL}
                    disabled={scanning || !settings?.enabled}
                    className="btn-primary"
                  >
                    {scanning ? (
                      <>
                        <Activity className="spinning" size={18} />
                        Scanning...
                      </>
                    ) : (
                      <>
                        <Search size={18} />
                        Scan URL
                      </>
                    )}
                  </button>
                </div>

                {!settings?.enabled && (
                  <div className="warning-message">
                    <AlertTriangle size={16} />
                    Web protection is disabled. Enable it in Settings tab.
                  </div>
                )}
              </div>

              {/* Scan Results */}
              {scanResult && (
                <motion.div
                  className="scan-results"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                >
                  <div className={`result-header ${scanResult.safe ? 'safe' : getRiskColor(scanResult.riskScore)}`}>
                    <div className="result-status">
                      {scanResult.safe ? (
                        <>
                          <CheckCircle size={32} />
                          <div>
                            <h3>✅ Safe URL</h3>
                            <p>No threats detected</p>
                          </div>
                        </>
                      ) : (
                        <>
                          <AlertTriangle size={32} />
                          <div>
                            <h3>⚠️ Dangerous URL</h3>
                            <p>{scanResult.threats.length} threat(s) detected</p>
                          </div>
                        </>
                      )}
                    </div>
                    <div className="risk-score">
                      <div className="score-value" style={{ color: getSeverityColor(getRiskColor(scanResult.riskScore)) }}>
                        {scanResult.riskScore}
                      </div>
                      <div className="score-label">Risk Score</div>
                    </div>
                  </div>

                  <div className="result-details">
                    <div className="detail-item">
                      <strong>URL:</strong>
                      <span className="url-text">{scanResult.url}</span>
                    </div>
                    <div className="detail-item">
                      <strong>Scanned:</strong>
                      <span>{new Date(scanResult.scannedAt).toLocaleString()}</span>
                    </div>
                  </div>

                  {/* Threats */}
                  {scanResult.threats.length > 0 && (
                    <div className="threats-section">
                      <h4>
                        <AlertTriangle size={18} />
                        Detected Threats
                      </h4>
                      <div className="threats-list">
                        {scanResult.threats.map((threat, index) => (
                          <div key={index} className={`threat-item ${threat.severity}`}>
                            <div className="threat-icon">
                              <AlertTriangle size={20} />
                            </div>
                            <div className="threat-info">
                              <div className="threat-header">
                                <span className="threat-desc">{threat.description}</span>
                                <span className={`severity-badge ${threat.severity}`}>
                                  {threat.severity.toUpperCase()}
                                </span>
                              </div>
                              <div className="threat-meta">
                                <span>Type: {threat.type}</span>
                                {threat.category && <span>Category: {threat.category}</span>}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Warnings */}
                  {scanResult.warnings && scanResult.warnings.length > 0 && (
                    <div className="warnings-section">
                      <h4>
                        <Info size={18} />
                        Warnings
                      </h4>
                      <div className="warnings-list">
                        {scanResult.warnings.map((warning, index) => (
                          <div key={index} className="warning-item">
                            <Info size={16} />
                            <span>{warning.description}</span>
                            {warning.score && <span className="warning-score">+{warning.score}</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Risk Progress Bar */}
                  <div className="risk-progress">
                    <div className="progress-label">
                      <span>Risk Level</span>
                      <span>{scanResult.riskScore}/100</span>
                    </div>
                    <div className="progress-bar">
                      <div
                        className={`progress-fill ${getRiskColor(scanResult.riskScore)}`}
                        style={{ width: `${scanResult.riskScore}%` }}
                      />
                    </div>
                  </div>
                </motion.div>
              )}
            </div>
          )}

          {/* BLOCKLIST TAB */}
          {activeTab === 'blocklist' && (
            <div className="blocklist-section">
              <div className="section-header">
                <h3>
                  <Ban size={20} />
                  Blocked Domains ({blockedDomains.length})
                </h3>
              </div>

              <div className="add-domain">
                <input
                  type="text"
                  value={newBlockedDomain}
                  onChange={(e) => setNewBlockedDomain(e.target.value)}
                  placeholder="Enter domain to block (e.g., malware-site.com)"
                  onKeyPress={(e) => e.key === 'Enter' && handleBlockDomain()}
                />
                <button onClick={handleBlockDomain} className="btn-danger">
                  <Plus size={18} />
                  Block Domain
                </button>
              </div>

              <div className="domains-list">
                {blockedDomains.length === 0 ? (
                  <div className="empty-state">
                    <Ban size={48} />
                    <h3>No blocked domains</h3>
                    <p>Add domains to block them from being accessed</p>
                  </div>
                ) : (
                  blockedDomains.map((domain, index) => (
                    <motion.div
                      key={index}
                      className="domain-item"
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.05 }}
                    >
                      <Ban size={18} className="domain-icon" />
                      <span className="domain-name">{domain}</span>
                      <button
                        onClick={() => handleUnblockDomain(domain)}
                        className="btn-sm btn-secondary"
                      >
                        <X size={14} />
                        Unblock
                      </button>
                    </motion.div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* ALLOWLIST TAB */}
          {activeTab === 'allowlist' && (
            <div className="allowlist-section">
              <div className="section-header">
                <h3>
                  <Check size={20} />
                  Allowed Domains ({allowedDomains.length})
                </h3>
              </div>

              <div className="add-domain">
                <input
                  type="text"
                  value={newAllowedDomain}
                  onChange={(e) => setNewAllowedDomain(e.target.value)}
                  placeholder="Enter domain to allow (e.g., trusted-site.com)"
                  onKeyPress={(e) => e.key === 'Enter' && handleAddToAllowlist()}
                />
                <button onClick={handleAddToAllowlist} className="btn-success">
                  <Plus size={18} />
                  Add to Allowlist
                </button>
              </div>

              <div className="domains-list">
                {allowedDomains.length === 0 ? (
                  <div className="empty-state">
                    <Check size={48} />
                    <h3>No allowed domains</h3>
                    <p>Add trusted domains to always allow them</p>
                  </div>
                ) : (
                  allowedDomains.map((domain, index) => (
                    <motion.div
                      key={index}
                      className="domain-item allowed"
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.05 }}
                    >
                      <Check size={18} className="domain-icon" />
                      <span className="domain-name">{domain}</span>
                      <button
                        onClick={() => handleRemoveFromAllowlist(domain)}
                        className="btn-sm btn-secondary"
                      >
                        <X size={14} />
                        Remove
                      </button>
                    </motion.div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* HISTORY TAB */}
          {activeTab === 'history' && (
            <div className="history-section">
              <div className="section-header">
                <h3>
                  <Clock size={20} />
                  Scan History ({scanHistory.length})
                </h3>
                {scanHistory.length > 0 && (
                  <button onClick={handleClearHistory} className="btn-secondary">
                    <Trash2 size={16} />
                    Clear History
                  </button>
                )}
              </div>

              <div className="history-filters">
                <div className="search-box">
                  <Search size={16} />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search URLs..."
                  />
                </div>
                <select
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                  className="filter-select"
                >
                  <option value="all">All Scans</option>
                  <option value="safe">Safe Only</option>
                  <option value="threats">Threats Only</option>
                </select>
              </div>

              <div className="history-list">
                {filteredHistory.length === 0 ? (
                  <div className="empty-state">
                    <Clock size={48} />
                    <h3>No scan history</h3>
                    <p>Scan URLs to see history here</p>
                  </div>
                ) : (
                  filteredHistory.map((scan, index) => (
                    <motion.div
                      key={index}
                      className={`history-item ${scan.safe ? 'safe' : 'threat'}`}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: index * 0.05 }}
                    >
                      <div className="history-icon">
                        {scan.safe ? (
                          <CheckCircle size={24} className="safe" />
                        ) : (
                          <AlertTriangle size={24} className="danger" />
                        )}
                      </div>
                      <div className="history-info">
                        <div className="history-url">{scan.url}</div>
                        <div className="history-meta">
                          <span>
                            <Clock size={12} />
                            {new Date(scan.scannedAt).toLocaleString()}
                          </span>
                          {!scan.safe && (
                            <>
                              <span className="threat-count">
                                {scan.threatsCount} threat(s)
                              </span>
                              <span className={`risk-badge ${getRiskColor(scan.riskScore)}`}>
                                Risk: {scan.riskScore}
                              </span>
                            </>
                          )}
                        </div>
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* SETTINGS TAB */}
          {activeTab === 'settings' && settings && (
            <div className="settings-section">
              <div className="section-header">
                <h3>
                  <Settings size={20} />
                  Protection Settings
                </h3>
                <button onClick={handleResetStatistics} className="btn-secondary">
                  <Trash2 size={16} />
                  Reset Statistics
                </button>
              </div>

              <div className="settings-list">
                <div className="setting-item">
                  <div className="setting-info">
                    <div className="setting-icon">
                      {settings.enabled ? <Shield size={24} /> : <X size={24} />}
                    </div>
                    <div>
                      <h4>Web Protection</h4>
                      <p>Enable or disable all web protection features</p>
                    </div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={settings.enabled}
                      onChange={(e) => handleToggleSetting('enabled', e.target.checked)}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <div className="setting-item">
                  <div className="setting-info">
                    <div className="setting-icon">
                      {settings.realTimeProtection ? <Eye size={24} /> : <EyeOff size={24} />}
                    </div>
                    <div>
                      <h4>Real-Time Protection</h4>
                      <p>Monitor and block threats in real-time</p>
                    </div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={settings.realTimeProtection}
                      onChange={(e) => handleToggleSetting('realTimeProtection', e.target.checked)}
                      disabled={!settings.enabled}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <div className="setting-item">
                  <div className="setting-info">
                    <div className="setting-icon">
                      <Ban size={24} />
                    </div>
                    <div>
                      <h4>Block Phishing</h4>
                      <p>Block phishing websites and scam attempts</p>
                    </div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={settings.blockPhishing}
                      onChange={(e) => handleToggleSetting('blockPhishing', e.target.checked)}
                      disabled={!settings.enabled}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <div className="setting-item">
                  <div className="setting-info">
                    <div className="setting-icon">
                      <AlertTriangle size={24} />
                    </div>
                    <div>
                      <h4>Block Malware</h4>
                      <p>Block malicious websites and malware downloads</p>
                    </div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={settings.blockMalware}
                      onChange={(e) => handleToggleSetting('blockMalware', e.target.checked)}
                      disabled={!settings.enabled}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <div className="setting-item">
                  <div className="setting-info">
                    <div className="setting-icon">
                      {settings.requireHTTPS ? <Lock size={24} /> : <Unlock size={24} />}
                    </div>
                    <div>
                      <h4>Require HTTPS</h4>
                      <p>Warn about websites without SSL/TLS encryption</p>
                    </div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={settings.requireHTTPS}
                      onChange={(e) => handleToggleSetting('requireHTTPS', e.target.checked)}
                      disabled={!settings.enabled}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>

              {/* Export/Import */}
              <div className="import-export">
                <h4>Backup & Restore</h4>
                <div className="backup-buttons">
                  <button onClick={handleExportSettings} className="btn-primary">
                    <Download size={18} />
                    Export Settings
                  </button>
                  <label className="btn-primary">
                    <Upload size={18} />
                    Import Settings
                    <input
                      type="file"
                      accept=".json"
                      onChange={handleImportSettings}
                      style={{ display: 'none' }}
                    />
                  </label>
                </div>
              </div>

              {/* Statistics Summary */}
              {statistics && (
                <div className="stats-summary">
                  <h4>
                    <BarChart3 size={18} />
                    Statistics Summary
                  </h4>
                  <div className="stats-details">
                    <div className="stat-row">
                      <span>Blocked Domains:</span>
                      <strong>{statistics.blockedDomainsCount}</strong>
                    </div>
                    <div className="stat-row">
                      <span>Allowed Domains:</span>
                      <strong>{statistics.allowedDomainsCount}</strong>
                    </div>
                    <div className="stat-row">
                      <span>Threat Database:</span>
                      <strong>{statistics.threatDatabaseSize} entries</strong>
                    </div>
                    <div className="stat-row">
                      <span>SSL Issues Detected:</span>
                      <strong>{statistics.sslIssuesDetected}</strong>
                    </div>
                    <div className="stat-row">
                      <span>Malware Blocked:</span>
                      <strong>{statistics.malwareBlocked}</strong>
                    </div>
                    {statistics.lastScan && (
                      <div className="stat-row">
                        <span>Last Scan:</span>
                        <strong>{new Date(statistics.lastScan).toLocaleString()}</strong>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

export default EnhancedWebProtection;
