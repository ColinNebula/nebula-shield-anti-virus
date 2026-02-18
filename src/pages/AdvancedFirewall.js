import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  XCircle,
  Eye,
  Lock,
  Unlock,
  TrendingUp,
  Globe,
  Zap,
  Filter
} from 'lucide-react';
import { dpi, ips, appFirewall, THREAT_DATABASE, GEO_IP_DATABASE } from '../services/advancedFirewall';
import './AdvancedFirewall.css';

const AdvancedFirewall = () => {
  // Load saved settings from localStorage (persists across crashes/refreshes/disconnects)
  const loadSavedSettings = () => {
    try {
      const saved = localStorage.getItem('nebula_firewall_settings');
      if (saved) {
        const parsed = JSON.parse(saved);
        console.log('Loaded firewall settings from localStorage');
        return parsed;
      }
    } catch (error) {
      console.error('Failed to load firewall settings from localStorage:', error);
    }
    return null;
  };

  const savedSettings = loadSavedSettings();

  const normalizeAppList = (list) => {
    if (!Array.isArray(list)) return [];
    const normalized = list
      .map((value) => {
        if (typeof appFirewall.normalizeProcessName === 'function') {
          return appFirewall.normalizeProcessName(value);
        }
        return (value || '').trim().toLowerCase();
      })
      .filter(Boolean);

    return Array.from(new Set(normalized));
  };

  const getInitialTrustedApps = () => {
    const source = Array.isArray(savedSettings?.trustedApps)
      ? savedSettings.trustedApps
      : Array.from(appFirewall.trustedApps);
    return normalizeAppList(source);
  };

  const getInitialBlockedApps = () => {
    const source = Array.isArray(savedSettings?.blockedApps)
      ? savedSettings.blockedApps
      : Array.from(appFirewall.blockedApps);
    const normalizedBlocked = normalizeAppList(source);
    const trusted = new Set(getInitialTrustedApps());
    return normalizedBlocked.filter(app => !trusted.has(app));
  };

  const [activeTab, setActiveTab] = useState(savedSettings?.activeTab ?? 0);
  const [dpiEnabled, setDpiEnabled] = useState(savedSettings?.dpiEnabled ?? true);
  const [ipsEnabled, setIpsEnabled] = useState(savedSettings?.ipsEnabled ?? true);
  const [appFirewallEnabled, setAppFirewallEnabled] = useState(savedSettings?.appFirewallEnabled ?? true);
  const [geoBlockingEnabled, setGeoBlockingEnabled] = useState(savedSettings?.geoBlockingEnabled ?? false);
  
  const [realtimeThreats, setRealtimeThreats] = useState(savedSettings?.realtimeThreats ?? []);
  const [blockedCountries, setBlockedCountries] = useState(savedSettings?.blockedCountries ?? []);
  const [trustedApps, setTrustedApps] = useState(() => getInitialTrustedApps());
  const [blockedApps, setBlockedApps] = useState(() => getInitialBlockedApps());
  const [newTrustedApp, setNewTrustedApp] = useState('');
  const [dpiStats, setDpiStats] = useState(savedSettings?.dpiStats ?? {
    packetsInspected: 15847,
    threatsDetected: 23,
    threatsBlocked: 23,
    cleanPackets: 15824
  });

  const [ipsAlerts, setIpsAlerts] = useState(savedSettings?.ipsAlerts ?? [
    {
      id: 1,
      timestamp: new Date(Date.now() - 300000).toISOString(),
      severity: 'high',
      name: 'Brute Force SSH Attempt',
      sourceIP: '192.168.1.245',
      action: 'blocked',
      details: 'Multiple failed SSH login attempts detected'
    },
    {
      id: 2,
      timestamp: new Date(Date.now() - 600000).toISOString(),
      severity: 'critical',
      name: 'SQL Injection Detected',
      sourceIP: '203.0.113.45',
      action: 'blocked',
      details: 'SQL injection attempt in HTTP POST request'
    },
    {
      id: 3,
      timestamp: new Date(Date.now() - 900000).toISOString(),
      severity: 'medium',
      name: 'Port Scanning Detected',
      sourceIP: '198.51.100.78',
      action: 'rate_limited',
      details: 'Scanning ports 1-1024'
    }
  ]);

  const tabs = [
    { id: 0, label: 'Deep Packet Inspection', icon: Eye },
    { id: 1, label: 'Intrusion Prevention', icon: ShieldAlert },
    { id: 2, label: 'Application Firewall', icon: Lock },
    { id: 3, label: 'Geo-Blocking', icon: Globe }
  ];

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return '#dc3545';
      case 'high': return '#fd7e14';
      case 'medium': return '#ffc107';
      case 'low': return '#17a2b8';
      default: return '#6c757d';
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <XCircle size={18} />;
      case 'medium':
        return <AlertTriangle size={18} />;
      default:
        return <CheckCircle2 size={18} />;
    }
  };

  const normalizeAppName = (value) => {
    if (typeof appFirewall.normalizeProcessName === 'function') {
      return appFirewall.normalizeProcessName(value);
    }
    return (value || '').trim().toLowerCase();
  };

  const handleAddTrustedApp = () => {
    const normalized = normalizeAppName(newTrustedApp);
    if (!normalized) return;

    appFirewall.trustApplication(normalized);
    setTrustedApps(prev => (prev.includes(normalized) ? prev : [normalized, ...prev]));
    setBlockedApps(prev => prev.filter(app => app !== normalized));
    setNewTrustedApp('');
  };

  const handleUntrustApp = (app) => {
    setTrustedApps(prev => prev.filter(item => item !== app));
  };

  const handleBlockApp = (app) => {
    appFirewall.blockApplication(app);
    setTrustedApps(prev => prev.filter(item => item !== app));
    setBlockedApps(prev => (prev.includes(app) ? prev : [app, ...prev]));
  };

  const handleUnblockApp = (app) => {
    setBlockedApps(prev => prev.filter(item => item !== app));
  };

  useEffect(() => {
    appFirewall.trustedApps.clear();
    trustedApps.forEach(app => appFirewall.trustedApps.add(app));
    appFirewall.blockedApps.clear();
    blockedApps.forEach(app => appFirewall.blockedApps.add(app));
  }, [trustedApps, blockedApps]);

  // Auto-save all firewall settings to localStorage (persists across crashes/refreshes/disconnects)
  useEffect(() => {
    try {
      const firewallSettings = {
        activeTab,
        dpiEnabled,
        ipsEnabled,
        appFirewallEnabled,
        geoBlockingEnabled,
        realtimeThreats,
        blockedCountries,
        trustedApps,
        blockedApps,
        dpiStats,
        ipsAlerts,
        lastSaved: new Date().toISOString()
      };
      localStorage.setItem('nebula_firewall_settings', JSON.stringify(firewallSettings));
      console.log('Firewall settings auto-saved to localStorage');
    } catch (error) {
      console.error('Failed to save firewall settings to localStorage:', error);
    }
  }, [activeTab, dpiEnabled, ipsEnabled, appFirewallEnabled, geoBlockingEnabled, 
      realtimeThreats, blockedCountries, trustedApps, blockedApps, dpiStats, ipsAlerts]);

  useEffect(() => {
    // Simulate real-time threat detection
    const interval = setInterval(() => {
      if (Math.random() < 0.1) { // 10% chance of new threat
        const threats = [
          { type: 'SQL Injection', severity: 'high', ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}` },
          { type: 'XSS Attack', severity: 'medium', ip: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}` },
          { type: 'Port Scan', severity: 'low', ip: `172.16.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}` },
          { type: 'C2 Communication', severity: 'critical', ip: `203.0.113.${Math.floor(Math.random() * 255)}` }
        ];
        
        const newThreat = threats[Math.floor(Math.random() * threats.length)];
        setRealtimeThreats(prev => [
          { ...newThreat, id: Date.now(), timestamp: new Date().toISOString() },
          ...prev.slice(0, 9) // Keep last 10
        ]);
        
        setDpiStats(prev => ({
          packetsInspected: prev.packetsInspected + Math.floor(Math.random() * 100),
          threatsDetected: prev.threatsDetected + 1,
          threatsBlocked: prev.threatsBlocked + 1,
          cleanPackets: prev.cleanPackets + Math.floor(Math.random() * 100)
        }));
      }
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="advanced-firewall">
      <div className="firewall-header">
        <div className="header-content">
          <ShieldCheck size={40} className="header-icon" />
          <div>
            <h1>Advanced Firewall Protection</h1>
            <p>Multi-layered threat detection and prevention system</p>
          </div>
        </div>

        <div className="protection-toggles">
          <motion.button
            className={`toggle-btn ${dpiEnabled ? 'active' : ''}`}
            onClick={() => setDpiEnabled(!dpiEnabled)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <Eye size={18} />
            Deep Packet Inspection
            <span className={`status-indicator ${dpiEnabled ? 'on' : 'off'}`}></span>
          </motion.button>

          <motion.button
            className={`toggle-btn ${ipsEnabled ? 'active' : ''}`}
            onClick={() => setIpsEnabled(!ipsEnabled)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <ShieldAlert size={18} />
            IPS
            <span className={`status-indicator ${ipsEnabled ? 'on' : 'off'}`}></span>
          </motion.button>

          <motion.button
            className={`toggle-btn ${appFirewallEnabled ? 'active' : ''}`}
            onClick={() => setAppFirewallEnabled(!appFirewallEnabled)}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <Lock size={18} />
            App Firewall
            <span className={`status-indicator ${appFirewallEnabled ? 'on' : 'off'}`}></span>
          </motion.button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="stats-grid">
        <motion.div className="stat-card" whileHover={{ y: -5 }}>
          <div className="stat-icon green">
            <Shield size={24} />
          </div>
          <div className="stat-content">
            <h3>{dpiStats.packetsInspected.toLocaleString()}</h3>
            <p>Packets Inspected</p>
          </div>
        </motion.div>

        <motion.div className="stat-card" whileHover={{ y: -5 }}>
          <div className="stat-icon red">
            <AlertTriangle size={24} />
          </div>
          <div className="stat-content">
            <h3>{dpiStats.threatsDetected}</h3>
            <p>Threats Detected</p>
          </div>
        </motion.div>

        <motion.div className="stat-card" whileHover={{ y: -5 }}>
          <div className="stat-icon blue">
            <Ban size={24} />
          </div>
          <div className="stat-content">
            <h3>{dpiStats.threatsBlocked}</h3>
            <p>Threats Blocked</p>
          </div>
        </motion.div>

        <motion.div className="stat-card" whileHover={{ y: -5 }}>
          <div className="stat-icon green">
            <CheckCircle2 size={24} />
          </div>
          <div className="stat-content">
            <h3>{((dpiStats.cleanPackets / dpiStats.packetsInspected) * 100).toFixed(1)}%</h3>
            <p>Clean Traffic</p>
          </div>
        </motion.div>
      </div>

      {/* Tabs */}
      <div className="firewall-tabs">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <motion.button
              key={tab.id}
              className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <Icon size={20} />
              {tab.label}
            </motion.button>
          );
        })}
      </div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          transition={{ duration: 0.2 }}
          className="tab-content"
        >
          {/* Deep Packet Inspection Tab */}
          {activeTab === 0 && (
            <div className="dpi-content">
              <div className="section-header">
                <Eye size={24} />
                <h2>Deep Packet Inspection</h2>
                <span className={`status-badge ${dpiEnabled ? 'active' : 'inactive'}`}>
                  {dpiEnabled ? 'Active' : 'Inactive'}
                </span>
              </div>

              <div className="info-card">
                <h3>What is DPI?</h3>
                <p>
                  Deep Packet Inspection examines the data part (and possibly the header) of network packets 
                  as they pass through an inspection point, searching for protocol non-compliance, viruses, 
                  spam, intrusions, or predefined criteria to decide whether the packet may pass.
                </p>
              </div>

              <h3>Detection Capabilities</h3>
              <div className="capabilities-grid">
                <div className="capability-card">
                  <Zap className="capability-icon" size={20} />
                  <h4>Exploit Kits</h4>
                  <p>{THREAT_DATABASE.exploitKits.length} signatures</p>
                </div>
                <div className="capability-card">
                  <Shield className="capability-icon" size={20} />
                  <h4>C2 Patterns</h4>
                  <p>{THREAT_DATABASE.c2Patterns.length} patterns</p>
                </div>
                <div className="capability-card">
                  <AlertTriangle className="capability-icon" size={20} />
                  <h4>Malware Families</h4>
                  <p>{THREAT_DATABASE.malwareFamilies.length} families</p>
                </div>
                <div className="capability-card">
                  <Ban className="capability-icon" size={20} />
                  <h4>Exploit Signatures</h4>
                  <p>{THREAT_DATABASE.exploitSignatures.length} signatures</p>
                </div>
              </div>

              <h3>Real-Time Threat Detection</h3>
              <div className="threats-list">
                {realtimeThreats.length === 0 ? (
                  <div className="empty-state">
                    <CheckCircle2 size={48} />
                    <p>No threats detected in the last 60 seconds</p>
                  </div>
                ) : (
                  realtimeThreats.map((threat) => (
                    <motion.div
                      key={threat.id}
                      className="threat-item"
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: 20 }}
                    >
                      <div className="threat-severity" style={{ backgroundColor: getSeverityColor(threat.severity) }}>
                        {getSeverityIcon(threat.severity)}
                      </div>
                      <div className="threat-details">
                        <h4>{threat.type}</h4>
                        <p>Source: {threat.ip}</p>
                      </div>
                      <div className="threat-time">
                        {new Date(threat.timestamp).toLocaleTimeString()}
                      </div>
                      <div className="threat-action blocked">
                        <Ban size={16} />
                        Blocked
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Intrusion Prevention Tab */}
          {activeTab === 1 && (
            <div className="ips-content">
              <div className="section-header">
                <ShieldAlert size={24} />
                <h2>Intrusion Prevention System</h2>
                <span className={`status-badge ${ipsEnabled ? 'active' : 'inactive'}`}>
                  {ipsEnabled ? 'Active' : 'Inactive'}
                </span>
              </div>

              <div className="info-card">
                <h3>Active Protection</h3>
                <p>
                  IPS monitors network traffic for malicious activity and takes immediate action to prevent 
                  security breaches. It can detect and block attacks in real-time based on signatures and behavior analysis.
                </p>
              </div>

              <h3>Recent Alerts ({ipsAlerts.length})</h3>
              <div className="alerts-list">
                {ipsAlerts.map((alert) => (
                  <motion.div
                    key={alert.id}
                    className="alert-card"
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    whileHover={{ scale: 1.02 }}
                  >
                    <div className="alert-header">
                      <div className="alert-severity" style={{ backgroundColor: getSeverityColor(alert.severity) }}>
                        {alert.severity.toUpperCase()}
                      </div>
                      <h4>{alert.name}</h4>
                      <span className={`action-badge ${alert.action}`}>
                        {alert.action === 'blocked' && <Ban size={14} />}
                        {alert.action}
                      </span>
                    </div>
                    <div className="alert-details">
                      <div className="detail-row">
                        <span className="label">Source IP:</span>
                        <span className="value">{alert.sourceIP}</span>
                      </div>
                      <div className="detail-row">
                        <span className="label">Time:</span>
                        <span className="value">{new Date(alert.timestamp).toLocaleString()}</span>
                      </div>
                      <div className="detail-row">
                        <span className="label">Details:</span>
                        <span className="value">{alert.details}</span>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>

              <h3>Signature Database</h3>
              <div className="signatures-grid">
                {ips.signatures.slice(0, 5).map((sig) => (
                  <div key={sig.id} className="signature-card">
                    <div className="sig-header">
                      <code>{sig.id}</code>
                      <span className={`severity-badge ${sig.severity}`}>{sig.severity}</span>
                    </div>
                    <h4>{sig.name}</h4>
                    <p>Action: <strong>{sig.action}</strong></p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Application Firewall Tab */}
          {activeTab === 2 && (
            <div className="app-firewall-content">
              <div className="section-header">
                <Lock size={24} />
                <h2>Application-Level Firewall</h2>
                <span className={`status-badge ${appFirewallEnabled ? 'active' : 'inactive'}`}>
                  {appFirewallEnabled ? 'Active' : 'Inactive'}
                </span>
              </div>

              <div className="info-card">
                <h3>Application Control</h3>
                <p>
                  Control which applications can access the network. Block unauthorized programs, 
                  restrict destinations, and monitor application behavior.
                </p>
              </div>

              <div className="app-controls">
                <input
                  className="app-input"
                  type="text"
                  placeholder="Add trusted app (e.g., chrome.exe or C:\\Program Files\\App\\app.exe)"
                  value={newTrustedApp}
                  onChange={(event) => setNewTrustedApp(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') {
                      event.preventDefault();
                      handleAddTrustedApp();
                    }
                  }}
                />
                <button
                  className="btn-primary"
                  onClick={handleAddTrustedApp}
                  disabled={!newTrustedApp.trim()}
                >
                  Trust App
                </button>
              </div>

              <h3>Trusted Applications ({trustedApps.length})</h3>
              <div className="apps-list">
                {trustedApps.length === 0 ? (
                  <div className="empty-state">
                    <CheckCircle2 size={48} />
                    <p>No trusted applications configured</p>
                  </div>
                ) : (
                  trustedApps.map((app) => (
                    <motion.div
                      key={app}
                      className="app-card trusted"
                      whileHover={{ scale: 1.02 }}
                    >
                      <div className="app-icon">
                        <CheckCircle2 size={24} />
                      </div>
                      <div className="app-info">
                        <h4>{app}</h4>
                        <p>Full network access</p>
                      </div>
                      <div className="app-actions">
                        <button className="btn-secondary" onClick={() => handleUntrustApp(app)}>
                          Untrust
                        </button>
                        <button className="btn-primary" onClick={() => handleBlockApp(app)}>
                          Block
                        </button>
                      </div>
                    </motion.div>
                  ))
                )}
              </div>

              <h3>Blocked Applications ({blockedApps.length})</h3>
              {blockedApps.length === 0 ? (
                <div className="empty-state">
                  <Unlock size={48} />
                  <p>No applications currently blocked</p>
                </div>
              ) : (
                <div className="apps-list">
                  {blockedApps.map((app) => (
                    <motion.div
                      key={app}
                      className="app-card blocked"
                      whileHover={{ scale: 1.02 }}
                    >
                      <div className="app-icon">
                        <XCircle size={24} />
                      </div>
                      <div className="app-info">
                        <h4>{app}</h4>
                        <p>Network access denied</p>
                      </div>
                      <button className="btn-primary" onClick={() => handleUnblockApp(app)}>
                        Unblock
                      </button>
                    </motion.div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Geo-Blocking Tab */}
          {activeTab === 3 && (
            <div className="geo-blocking-content">
              <div className="section-header">
                <Globe size={24} />
                <h2>Geographic Blocking</h2>
                <span className={`status-badge ${geoBlockingEnabled ? 'active' : 'inactive'}`}>
                  {geoBlockingEnabled ? 'Active' : 'Inactive'}
                </span>
              </div>

              <div className="info-card">
                <h3>Geo-IP Filtering</h3>
                <p>
                  Block traffic from specific countries or regions. Useful for preventing attacks 
                  from high-risk geographic locations.
                </p>
              </div>

              <div className="geo-controls">
                <motion.button
                  className={`geo-toggle ${geoBlockingEnabled ? 'active' : ''}`}
                  onClick={() => setGeoBlockingEnabled(!geoBlockingEnabled)}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  {geoBlockingEnabled ? <Lock size={20} /> : <Unlock size={20} />}
                  {geoBlockingEnabled ? 'Disable' : 'Enable'} Geo-Blocking
                </motion.button>
              </div>

              <h3>High-Risk Countries</h3>
              <div className="countries-grid">
                {GEO_IP_DATABASE.highRiskCountries.map((code) => {
                  const country = GEO_IP_DATABASE.countries[code];
                  const isBlocked = blockedCountries.includes(code);
                  
                  return (
                    <motion.div
                      key={code}
                      className={`country-card ${isBlocked ? 'blocked' : ''}`}
                      whileHover={{ scale: 1.05 }}
                      onClick={() => {
                        setBlockedCountries(prev => 
                          isBlocked 
                            ? prev.filter(c => c !== code)
                            : [...prev, code]
                        );
                      }}
                    >
                      <span className="flag">{country.flag}</span>
                      <h4>{country.name}</h4>
                      <span className={`risk-badge ${country.risk}`}>
                        {country.risk.toUpperCase()}
                      </span>
                      {isBlocked && (
                        <div className="blocked-overlay">
                          <Ban size={32} />
                        </div>
                      )}
                    </motion.div>
                  );
                })}
              </div>

              <h3>All Countries</h3>
              <div className="countries-list">
                {Object.entries(GEO_IP_DATABASE.countries)
                  .filter(([code]) => !GEO_IP_DATABASE.highRiskCountries.includes(code))
                  .map(([code, country]) => {
                    const isBlocked = blockedCountries.includes(code);
                    
                    return (
                      <div key={code} className="country-row">
                        <span className="flag-large">{country.flag}</span>
                        <div className="country-info">
                          <h4>{country.name}</h4>
                          <span className={`risk-text ${country.risk}`}>
                            {country.risk} risk
                          </span>
                        </div>
                        <motion.button
                          className={`block-btn ${isBlocked ? 'blocked' : ''}`}
                          onClick={() => {
                            setBlockedCountries(prev => 
                              isBlocked 
                                ? prev.filter(c => c !== code)
                                : [...prev, code]
                            );
                          }}
                          whileHover={{ scale: 1.1 }}
                          whileTap={{ scale: 0.9 }}
                        >
                          {isBlocked ? <Unlock size={16} /> : <Ban size={16} />}
                          {isBlocked ? 'Unblock' : 'Block'}
                        </motion.button>
                      </div>
                    );
                  })}
              </div>
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
};

export default AdvancedFirewall;
