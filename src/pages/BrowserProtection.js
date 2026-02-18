import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Cookie,
  Globe,
  Trash2,
  Search,
  AlertTriangle,
  CheckCircle,
  XCircle,
  TrendingUp,
  Activity,
  Lock,
  Unlock,
  RefreshCw,
  Settings,
  Info,
  BarChart3,
  Zap,
  Filter
} from 'lucide-react';
import axios from 'axios';
import toast from 'react-hot-toast';
import './BrowserProtection.css';

const API_BASE = 'http://localhost:3001/api';

const BrowserProtection = () => {
  const [activeTab, setActiveTab] = useState('scanner');
  const [loading, setLoading] = useState(false);
  const [scanDomain, setScanDomain] = useState('');
  const [scanResults, setScanResults] = useState(null);
  const [cookies, setCookies] = useState([]);
  const [stats, setStats] = useState(null);
  const [rules, setRules] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState('all');
  const [selectedCookies, setSelectedCookies] = useState([]);
  const [scanningPC, setScanningPC] = useState(false);
  const [pcScanResults, setPcScanResults] = useState(null);

  useEffect(() => {
    loadStats();
    loadRules();
  }, []);

  const loadStats = async () => {
    try {
      const response = await axios.get(`${API_BASE}/browser/cookies/stats`);
      if (response.data.success) {
        setStats(response.data.stats);
      }
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  };

  const loadRules = async () => {
    try {
      const response = await axios.get(`${API_BASE}/browser/cookies/rules`);
      if (response.data.success) {
        setRules(response.data.rules);
      }
    } catch (error) {
      console.error('Failed to load rules:', error);
    }
  };

  const handleScanCookies = async () => {
    if (!scanDomain) {
      toast.error('Please enter a domain to scan');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post(`${API_BASE}/browser/cookies/scan`, {
        domain: scanDomain
      });

      if (response.data.success) {
        setScanResults(response.data);
        setCookies(response.data.cookies);
        toast.success(`Found ${response.data.cookies.length} cookies`);
      }
    } catch (error) {
      toast.error('Scan failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleScanPCCookies = async () => {
    setScanningPC(true);
    try {
      const response = await axios.get(`${API_BASE}/browser/cookies`);

      if (response.data.success) {
        const pcCookies = response.data.cookies || [];
        const analyzed = pcCookies.map(c => ({
          ...c,
          id: `${c.domain}_${c.name}_${Math.random()}`,
          category: c.category || 'functional'
        }));
        
        setPcScanResults({
          totalCookies: analyzed.length,
          tracking: analyzed.filter(c => c.category === 'tracking').length,
          malicious: analyzed.filter(c => c.category === 'malicious').length,
          advertising: analyzed.filter(c => c.category === 'advertising').length,
          cookies: analyzed
        });
        setCookies(analyzed);
        toast.success(`Found ${analyzed.length} cookies on your PC`);
        setActiveTab('cookies');
      }
    } catch (error) {
      toast.error('PC scan failed: ' + error.message);
    } finally {
      setScanningPC(false);
    }
  };

  const handleDeleteAllTracking = async () => {
    const trackingCookies = cookies.filter(c => c.category === 'tracking');
    if (trackingCookies.length === 0) {
      toast.error('No tracking cookies found');
      return;
    }

    if (!window.confirm(`Delete ${trackingCookies.length} tracking cookies?`)) {
      return;
    }

    await handleDeleteCookies(null, 'tracking', null);
  };

  const handleDeleteAllMalicious = async () => {
    const maliciousCookies = cookies.filter(c => c.category === 'malicious');
    if (maliciousCookies.length === 0) {
      toast.error('No malicious cookies found');
      return;
    }

    if (!window.confirm(`Delete ${maliciousCookies.length} malicious cookies?`)) {
      return;
    }

    await handleDeleteCookies(null, 'malicious', null);
  };

  const handleDeleteCookies = async (domain, category, cookieIds) => {
    try {
      const response = await axios.post(`${API_BASE}/browser/cookies/delete`, {
        domain,
        category,
        cookieIds
      });

      if (response.data.success) {
        toast.success(response.data.message);
        setCookies(prev => prev.filter(c => !cookieIds?.includes(c.id)));
        setSelectedCookies([]);
        loadStats();
        
        // Update PC scan results if they exist
        if (pcScanResults) {
          const remaining = cookies.filter(c => !cookieIds?.includes(c.id));
          setPcScanResults({
            totalCookies: remaining.length,
            tracking: remaining.filter(c => c.category === 'tracking').length,
            malicious: remaining.filter(c => c.category === 'malicious').length,
            advertising: remaining.filter(c => c.category === 'advertising').length,
            cookies: remaining
          });
        }
      }
    } catch (error) {
      toast.error('Delete failed: ' + error.message);
    }
  };

  const handleToggleRule = async (ruleId, enabled) => {
    try {
      const response = await axios.post(`${API_BASE}/browser/cookies/rules/update`, {
        ruleId,
        enabled: !enabled
      });

      if (response.data.success) {
        setRules(prev => prev.map(r => 
          r.id === ruleId ? { ...r, enabled: !enabled } : r
        ));
        toast.success('Rule updated');
      }
    } catch (error) {
      toast.error('Failed to update rule');
    }
  };

  const getCategoryIcon = (category) => {
    const icons = {
      tracking: AlertTriangle,
      malicious: XCircle,
      advertising: TrendingUp,
      analytics: BarChart3,
      functional: CheckCircle,
      necessary: Lock
    };
    return icons[category] || Cookie;
  };

  const getCategoryColor = (category) => {
    const colors = {
      tracking: '#f59e0b',
      malicious: '#ef4444',
      advertising: '#8b5cf6',
      analytics: '#3b82f6',
      functional: '#10b981',
      necessary: '#6b7280'
    };
    return colors[category] || '#6b7280';
  };

  const getThreatBadge = (shouldBlock, category) => {
    if (shouldBlock) {
      return <span className="badge badge-danger">Blocked</span>;
    }
    if (category === 'malicious') {
      return <span className="badge badge-danger">Malicious</span>;
    }
    if (category === 'tracking') {
      return <span className="badge badge-warning">Tracking</span>;
    }
    return <span className="badge badge-success">Safe</span>;
  };

  const filteredCookies = cookies.filter(cookie => {
    const matchesSearch = cookie.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         cookie.domain.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = filterCategory === 'all' || cookie.category === filterCategory;
    return matchesSearch && matchesCategory;
  });

  const handleSelectAll = () => {
    if (selectedCookies.length === filteredCookies.length) {
      setSelectedCookies([]);
    } else {
      setSelectedCookies(filteredCookies.map(c => c.id));
    }
  };

  const handleSelectCookie = (cookieId) => {
    setSelectedCookies(prev => 
      prev.includes(cookieId) 
        ? prev.filter(id => id !== cookieId)
        : [...prev, cookieId]
    );
  };

  return (
    <motion.div 
      className="browser-protection"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
    >
      {/* Header */}
      <div className="page-header">
        <motion.h1
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
        >
          <Shield size={32} />
          Browser Protection
        </motion.h1>
        <motion.p
          className="page-subtitle"
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.1 }}
        >
          Monitor and manage website cookies, trackers, and privacy threats
        </motion.p>
      </div>

      {/* Statistics Dashboard */}
      {stats && (
        <motion.div 
          className="stats-grid"
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
        >
          <div className="stat-card primary">
            <div className="stat-icon">
              <Shield size={32} />
            </div>
            <div className="stat-content">
              <h3>{stats.totalBlocked?.toLocaleString() || 0}</h3>
              <p>Total Blocked</p>
            </div>
          </div>

          <div className="stat-card warning">
            <div className="stat-icon">
              <AlertTriangle size={32} />
            </div>
            <div className="stat-content">
              <h3>{stats.trackingBlocked?.toLocaleString() || 0}</h3>
              <p>Tracking Cookies</p>
            </div>
          </div>

          <div className="stat-card danger">
            <div className="stat-icon">
              <XCircle size={32} />
            </div>
            <div className="stat-content">
              <h3>{stats.maliciousBlocked || 0}</h3>
              <p>Malicious Blocked</p>
            </div>
          </div>

          <div className="stat-card success">
            <div className="stat-icon">
              <TrendingUp size={32} />
            </div>
            <div className="stat-content">
              <h3>{stats.privacyScore || 0}/100</h3>
              <p>Privacy Score</p>
            </div>
          </div>

          <div className="stat-card info">
            <div className="stat-icon">
              <Zap size={32} />
            </div>
            <div className="stat-content">
              <h3>{stats.todayBlocked || 0}</h3>
              <p>Blocked Today</p>
            </div>
          </div>

          <div className="stat-card accent">
            <div className="stat-icon">
              <Activity size={32} />
            </div>
            <div className="stat-content">
              <h3>{typeof stats.bandwidthSaved === 'number' ? stats.bandwidthSaved.toFixed(2) : (stats.bandwidthSaved || 0)} MB</h3>
              <p>Bandwidth Saved</p>
            </div>
          </div>
        </motion.div>
      )}

      {/* Tabs */}
      <motion.div 
        className="tabs"
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.3 }}
      >
        <button
          className={`tab ${activeTab === 'scanner' ? 'active' : ''}`}
          onClick={() => setActiveTab('scanner')}
        >
          <Search size={20} />
          Cookie Scanner
        </button>
        <button
          className={`tab ${activeTab === 'cookies' ? 'active' : ''}`}
          onClick={() => setActiveTab('cookies')}
        >
          <Cookie size={20} />
          Cookies ({cookies.length})
        </button>
        <button
          className={`tab ${activeTab === 'rules' ? 'active' : ''}`}
          onClick={() => setActiveTab('rules')}
        >
          <Settings size={20} />
          Blocking Rules ({rules.length})
        </button>
      </motion.div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        {activeTab === 'scanner' && (
          <motion.div
            key="scanner"
            className="tab-content"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <div className="scanner-section">
              {/* Domain Scanner */}
              <div className="scanner-box">
                <h3>
                  <Globe size={20} />
                  Scan Website Cookies
                </h3>
                <p>Analyze cookies from a specific website</p>
                <div className="scanner-input">
                  <Globe size={20} />
                  <input
                    type="text"
                    placeholder="Enter domain (e.g., facebook.com, google.com)"
                    value={scanDomain}
                    onChange={(e) => setScanDomain(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleScanCookies()}
                  />
                  <motion.button
                    className="btn btn-primary"
                    onClick={handleScanCookies}
                    disabled={loading}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    {loading ? (
                      <>
                        <RefreshCw size={18} className="spinning" />
                        Scanning...
                      </>
                    ) : (
                      <>
                        <Search size={18} />
                        Scan Website
                      </>
                    )}
                  </motion.button>
                </div>
              </div>

              {/* PC Cookie Scanner */}
              <div className="scanner-box pc-scanner">
                <h3>
                  <Shield size={20} />
                  Scan Your PC for Cookies
                </h3>
                <p>Find and resolve all cookies stored in your browsers</p>
                <div className="pc-scanner-actions">
                  <motion.button
                    className="btn btn-accent"
                    onClick={handleScanPCCookies}
                    disabled={scanningPC}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    {scanningPC ? (
                      <>
                        <RefreshCw size={18} className="spinning" />
                        Scanning PC...
                      </>
                    ) : (
                      <>
                        <Search size={18} />
                        Scan PC Cookies
                      </>
                    )}
                  </motion.button>

                  {pcScanResults && (
                    <>
                      <motion.button
                        className="btn btn-warning"
                        onClick={handleDeleteAllTracking}
                        disabled={pcScanResults.tracking === 0}
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                      >
                        <Trash2 size={18} />
                        Delete All Tracking ({pcScanResults.tracking})
                      </motion.button>

                      {pcScanResults.malicious > 0 && (
                        <motion.button
                          className="btn btn-danger"
                          onClick={handleDeleteAllMalicious}
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                        >
                          <AlertTriangle size={18} />
                          Delete Malicious ({pcScanResults.malicious})
                        </motion.button>
                      )}
                    </>
                  )}
                </div>

                {pcScanResults && (
                  <motion.div
                    className="pc-scan-summary"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                  >
                    <div className="summary-stat">
                      <Cookie size={16} />
                      <span>Total: {pcScanResults.totalCookies}</span>
                    </div>
                    <div className="summary-stat warning">
                      <AlertTriangle size={16} />
                      <span>Tracking: {pcScanResults.tracking}</span>
                    </div>
                    {pcScanResults.malicious > 0 && (
                      <div className="summary-stat danger">
                        <XCircle size={16} />
                        <span>Malicious: {pcScanResults.malicious}</span>
                      </div>
                    )}
                    <div className="summary-stat info">
                      <TrendingUp size={16} />
                      <span>Advertising: {pcScanResults.advertising}</span>
                    </div>
                  </motion.div>
                )}
              </div>

              {scanResults && (
                <motion.div
                  className="scan-results"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                >
                  <div className="results-header">
                    <h3>
                      <Shield size={24} />
                      Scan Results for {scanResults.domain}
                    </h3>
                    <span className="scan-time">
                      {new Date(scanResults.scanTime).toLocaleTimeString()}
                    </span>
                  </div>

                  <div className="results-stats">
                    <div className="result-stat">
                      <Cookie size={20} />
                      <span className="label">Total Cookies:</span>
                      <span className="value">{scanResults.stats.total}</span>
                    </div>
                    <div className="result-stat warning">
                      <AlertTriangle size={20} />
                      <span className="label">Tracking:</span>
                      <span className="value">{scanResults.stats.tracking}</span>
                    </div>
                    <div className="result-stat danger">
                      <XCircle size={20} />
                      <span className="label">Malicious:</span>
                      <span className="value">{scanResults.stats.malicious}</span>
                    </div>
                    <div className="result-stat info">
                      <Lock size={20} />
                      <span className="label">Blocked:</span>
                      <span className="value">{scanResults.stats.blocked}</span>
                    </div>
                  </div>

                  {scanResults.recommendations?.length > 0 && (
                    <div className="recommendations">
                      <h4>
                        <Info size={20} />
                        Recommendations
                      </h4>
                      <ul>
                        {scanResults.recommendations.map((rec, idx) => (
                          <li key={idx}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </motion.div>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === 'cookies' && (
          <motion.div
            key="cookies"
            className="tab-content"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <div className="cookies-section">
              <div className="cookies-controls">
                <div className="search-filter">
                  <div className="search-box">
                    <Search size={18} />
                    <input
                      type="text"
                      placeholder="Search cookies..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                  </div>

                  <div className="filter-box">
                    <Filter size={18} />
                    <select
                      value={filterCategory}
                      onChange={(e) => setFilterCategory(e.target.value)}
                    >
                      <option value="all">All Categories</option>
                      <option value="tracking">Tracking</option>
                      <option value="malicious">Malicious</option>
                      <option value="advertising">Advertising</option>
                      <option value="analytics">Analytics</option>
                      <option value="functional">Functional</option>
                      <option value="necessary">Necessary</option>
                    </select>
                  </div>
                </div>

                {selectedCookies.length > 0 && (
                  <motion.button
                    className="btn btn-danger"
                    onClick={() => handleDeleteCookies(null, null, selectedCookies)}
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Trash2 size={18} />
                    Delete Selected ({selectedCookies.length})
                  </motion.button>
                )}
              </div>

              {filteredCookies.length > 0 ? (
                <div className="cookies-list">
                  <div className="list-header">
                    <input
                      type="checkbox"
                      checked={selectedCookies.length === filteredCookies.length}
                      onChange={handleSelectAll}
                    />
                    <span>Name</span>
                    <span>Domain</span>
                    <span>Category</span>
                    <span>Status</span>
                    <span>Actions</span>
                  </div>

                  {filteredCookies.map((cookie) => {
                    const CategoryIcon = getCategoryIcon(cookie.category);
                    return (
                      <motion.div
                        key={cookie.id}
                        className="cookie-item"
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        whileHover={{ backgroundColor: 'rgba(255,255,255,0.02)' }}
                      >
                        <input
                          type="checkbox"
                          checked={selectedCookies.includes(cookie.id)}
                          onChange={() => handleSelectCookie(cookie.id)}
                        />
                        
                        <div className="cookie-name">
                          <CategoryIcon 
                            size={18} 
                            color={getCategoryColor(cookie.category)}
                          />
                          <span>{cookie.name}</span>
                        </div>

                        <div className="cookie-domain">
                          {cookie.domain}
                        </div>

                        <div className="cookie-category">
                          <span 
                            className="category-badge"
                            style={{ 
                              backgroundColor: getCategoryColor(cookie.category) + '20',
                              color: getCategoryColor(cookie.category)
                            }}
                          >
                            {cookie.category}
                          </span>
                        </div>

                        <div className="cookie-status">
                          {getThreatBadge(cookie.shouldBlock, cookie.category)}
                        </div>

                        <div className="cookie-actions">
                          <motion.button
                            className="btn-icon btn-danger"
                            onClick={() => handleDeleteCookies(cookie.domain, null, [cookie.id])}
                            whileHover={{ scale: 1.1 }}
                            whileTap={{ scale: 0.9 }}
                            title="Delete cookie"
                          >
                            <Trash2 size={16} />
                          </motion.button>
                        </div>
                      </motion.div>
                    );
                  })}
                </div>
              ) : (
                <div className="empty-state">
                  <Cookie size={64} />
                  <h3>No Cookies Found</h3>
                  <p>Scan a domain or your PC to view and manage cookies</p>
                  <motion.button
                    className="btn btn-primary"
                    onClick={() => setActiveTab('scanner')}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Search size={18} />
                    Start Scanning
                  </motion.button>
                </div>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === 'rules' && (
          <motion.div
            key="rules"
            className="tab-content"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <div className="rules-section">
              <div className="rules-header">
                <h3>
                  <Settings size={24} />
                  Cookie Blocking Rules
                </h3>
                <p>Configure automatic blocking rules based on cookie categories and threat levels</p>
              </div>

              <div className="rules-list">
                {rules.map((rule) => (
                  <motion.div
                    key={rule.id}
                    className={`rule-item ${rule.enabled ? 'enabled' : 'disabled'}`}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                  >
                    <div className="rule-header">
                      <div className="rule-info">
                        <h4>{rule.name}</h4>
                        <span className={`priority-badge ${rule.priority}`}>
                          {rule.priority} priority
                        </span>
                      </div>
                      
                      <motion.button
                        className={`toggle-btn ${rule.enabled ? 'active' : ''}`}
                        onClick={() => handleToggleRule(rule.id, rule.enabled)}
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                      >
                        {rule.enabled ? (
                          <>
                            <Lock size={18} />
                            Enabled
                          </>
                        ) : (
                          <>
                            <Unlock size={18} />
                            Disabled
                          </>
                        )}
                      </motion.button>
                    </div>

                    <div className="rule-details">
                      <div className="rule-meta">
                        <span>
                          <strong>Action:</strong> {rule.action}
                        </span>
                        {rule.category && (
                          <span>
                            <strong>Category:</strong> {rule.category}
                          </span>
                        )}
                        {rule.patterns && (
                          <span>
                            <strong>Patterns:</strong> {rule.patterns.length} rules
                          </span>
                        )}
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>

              <div className="rules-info">
                <Info size={20} />
                <div>
                  <h4>How Blocking Rules Work</h4>
                  <p>Rules are processed in order of priority (critical → high → medium → low). 
                     When a cookie matches a rule, the specified action is taken immediately.</p>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

export default BrowserProtection;
