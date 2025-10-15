import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  ShieldAlert,
  Eye,
  EyeOff,
  Lock,
  Unlock,
  FileText,
  Upload,
  Download,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Copy,
  Trash2,
  Search,
  Filter,
  FileCheck,
  Database,
  Scale,
  Fingerprint,
  CreditCard,
  Mail,
  Phone,
  MapPin,
  User,
  Key,
  Activity
} from 'lucide-react';
import { dataProtection, PII_PATTERNS, SENSITIVE_KEYWORDS } from '../services/dataProtection';
import toast from 'react-hot-toast';
import './DataProtection.css';

const DataProtection = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [scanText, setScanText] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [dataLeakAlerts, setDataLeakAlerts] = useState([]);
  const [statistics, setStatistics] = useState(dataProtection.getStatistics());
  const [selectedStandard, setSelectedStandard] = useState('GDPR');
  const [complianceReport, setComplianceReport] = useState(null);
  const [showRedacted, setShowRedacted] = useState(false);
  const [redactedText, setRedactedText] = useState('');
  const [gdprIdentifier, setGdprIdentifier] = useState('');
  const [gdprResult, setGdprResult] = useState(null);
  const [gdprAction, setGdprAction] = useState('dsar');
  const [anonymizedText, setAnonymizedText] = useState('');
  const [retentionDays, setRetentionDays] = useState(365);
  const fileInputRef = useRef(null);

  const tabs = [
    { id: 0, label: 'PII Scanner', icon: Search },
    { id: 1, label: 'Data Leak Prevention', icon: ShieldAlert },
    { id: 2, label: 'Compliance Reports', icon: Scale },
    { id: 3, label: 'GDPR Tools', icon: Shield },
    { id: 4, label: 'Statistics', icon: Activity }
  ];

  const categoryIcons = {
    financial: CreditCard,
    identity: Fingerprint,
    contact: Mail,
    network: Database,
    health: Activity,
    credentials: Key,
    location: MapPin,
    biometric: Fingerprint
  };

  const handleScan = () => {
    if (!scanText.trim()) {
      toast.error('Please enter text to scan');
      return;
    }

    setScanning(true);
    
    setTimeout(() => {
      const result = dataProtection.scanText(scanText, { 
        includeContext: true, 
        maskData: true 
      });
      
      setScanResult(result);
      setScanning(false);
      
      if (result.hasPII) {
        toast.error(`⚠️ Found ${result.findings.length} PII item(s)!`, {
          duration: 4000,
          icon: '🔒'
        });
      } else {
        toast.success('✅ No PII detected - Text is safe', {
          duration: 3000
        });
      }
      
      // Update statistics
      setStatistics(dataProtection.getStatistics());
    }, 800);
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    try {
      const text = await dataProtection.readFile(file);
      setScanText(text);
      toast.success(`File loaded: ${file.name}`);
    } catch (error) {
      toast.error('Failed to read file');
    }
  };

  const handleAnonymizeText = () => {
    if (!scanText.trim()) {
      toast.error('Please enter text to anonymize');
      return;
    }

    const result = dataProtection.anonymizeData(scanText, { method: 'generalization', k: 3 });
    
    if (result.success) {
      setAnonymizedText(result.anonymizedText);
      toast.success(`✅ Anonymized ${result.piiRemoved} PII items`);
    }
  };

  const handleGDPRAction = () => {
    if (!gdprIdentifier.trim()) {
      toast.error('Please enter an identifier (email, user ID, etc.)');
      return;
    }

    let result;
    switch (gdprAction) {
      case 'dsar':
        result = dataProtection.generateDSARReport(gdprIdentifier);
        toast.success('DSAR Report Generated');
        break;
      case 'export':
        result = dataProtection.exportPersonalData(gdprIdentifier, 'json');
        toast.success('Data Export Completed');
        break;
      case 'forget':
        result = dataProtection.rightToBeForgotten(gdprIdentifier);
        toast.success('Right to Be Forgotten Executed');
        setStatistics(dataProtection.getStatistics());
        break;
      case 'retention':
        result = dataProtection.applyRetentionPolicy(retentionDays);
        toast.success(`Retention Policy Applied: ${result.totalDeleted} items deleted`);
        setStatistics(dataProtection.getStatistics());
        break;
      default:
        result = { error: 'Unknown action' };
    }

    setGdprResult(result);
  };

  const downloadGDPRReport = () => {
    if (!gdprResult) return;

    const dataStr = JSON.stringify(gdprResult, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `gdpr_${gdprAction}_${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
    toast.success('Report downloaded');
  };

  const handleRedact = () => {
    if (!scanText.trim()) {
      toast.error('Please enter text to redact');
      return;
    }

    const result = dataProtection.redactPII(scanText, {
      redactionChar: '█',
      preserveFormat: true,
      keepFirstN: 0,
      keepLastN: 4
    });

    setRedactedText(result.redactedText);
    setShowRedacted(true);
    toast.success(`✅ Redacted ${result.redactionCount} PII item(s)`);
  };

  const handleCopyRedacted = () => {
    navigator.clipboard.writeText(redactedText);
    toast.success('📋 Redacted text copied to clipboard');
  };

  const simulateDataLeak = (source) => {
    const testData = scanText || 'SSN: 123-45-6789, Card: 4532-1234-5678-9010, Email: john.doe@example.com';
    const leakResult = dataProtection.detectDataLeak(source, testData);
    
    if (leakResult.isLeak) {
      setDataLeakAlerts([leakResult.alert, ...dataLeakAlerts]);
      
      if (leakResult.shouldBlock) {
        toast.error('🚨 DATA LEAK BLOCKED! Sensitive data detected.', {
          duration: 5000,
          icon: '🛡️'
        });
      } else {
        toast('⚠️ Potential data leak detected', {
          icon: '⚠️',
          duration: 4000
        });
      }
    } else {
      toast.success('✅ No sensitive data detected in leak test');
    }
    
    setStatistics(dataProtection.getStatistics());
  };

  const generateCompliance = () => {
    if (!scanResult) {
      toast.error('Please scan text first');
      return;
    }

    const report = dataProtection.generateComplianceReport(scanResult, selectedStandard);
    setComplianceReport(report);
    toast.success(`📊 ${selectedStandard} compliance report generated`);
  };

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
        return <XCircle size={18} />;
      case 'high':
        return <AlertTriangle size={18} />;
      case 'medium':
        return <AlertTriangle size={18} />;
      default:
        return <CheckCircle2 size={18} />;
    }
  };

  const getCategoryIcon = (category) => {
    const Icon = categoryIcons[category] || User;
    return <Icon size={18} />;
  };

  return (
    <div className="data-protection">
      <div className="protection-header">
        <div className="header-content">
          <Shield size={40} className="header-icon" />
          <div>
            <h1>Personal Data Protection</h1>
            <p>PII Detection, Data Leak Prevention & Compliance (GDPR/CCPA/HIPAA)</p>
          </div>
        </div>

        <div className="stats-mini">
          <div className="stat-mini">
            <FileCheck size={20} />
            <span>{statistics.totalScans} Scans</span>
          </div>
          <div className="stat-mini">
            <ShieldAlert size={20} />
            <span>{statistics.totalLeakAlerts} Alerts</span>
          </div>
          <div className="stat-mini critical">
            <AlertTriangle size={20} />
            <span>{statistics.criticalLeaks} Critical</span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="protection-tabs">
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
          {/* PII Scanner Tab */}
          {activeTab === 0 && (
            <div className="scanner-content">
              <div className="scanner-controls">
                <div className="input-section">
                  <h3>
                    <Search size={20} />
                    Scan for Personal Data (PII)
                  </h3>
                  <textarea
                    className="scan-textarea"
                    placeholder="Paste text to scan for PII... 

Examples:
• Credit Card: 4532-1234-5678-9010
• SSN: 123-45-6789
• Email: user@example.com
• Phone: (555) 123-4567
• Passport: AB1234567"
                    value={scanText}
                    onChange={(e) => setScanText(e.target.value)}
                    rows={12}
                  />
                  
                  <div className="control-buttons">
                    <motion.button
                      className="btn-primary"
                      onClick={handleScan}
                      disabled={scanning}
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <Search size={18} />
                      {scanning ? 'Scanning...' : 'Scan for PII'}
                    </motion.button>

                    <motion.button
                      className="btn-secondary"
                      onClick={handleRedact}
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <EyeOff size={18} />
                      Redact PII
                    </motion.button>

                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleFileUpload}
                      style={{ display: 'none' }}
                      accept=".txt,.doc,.docx,.pdf"
                    />
                    <motion.button
                      className="btn-secondary"
                      onClick={() => fileInputRef.current.click()}
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <Upload size={18} />
                      Scan File
                    </motion.button>

                    <motion.button
                      className="btn-danger"
                      onClick={() => {
                        setScanText('');
                        setScanResult(null);
                        setShowRedacted(false);
                      }}
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <Trash2 size={18} />
                      Clear
                    </motion.button>
                  </div>
                </div>

                {showRedacted && (
                  <motion.div
                    className="redacted-section"
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                  >
                    <h3>
                      <EyeOff size={20} />
                      Redacted Text
                    </h3>
                    <div className="redacted-textarea">
                      {redactedText}
                    </div>
                    <motion.button
                      className="btn-secondary"
                      onClick={handleCopyRedacted}
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      <Copy size={18} />
                      Copy Redacted Text
                    </motion.button>
                  </motion.div>
                )}
              </div>

              {scanResult && (
                <motion.div
                  className="scan-results"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                >
                  <div className="results-header">
                    <h3>
                      <FileCheck size={24} />
                      Scan Results
                    </h3>
                    <div className={`risk-badge ${scanResult.riskScore > 70 ? 'critical' : scanResult.riskScore > 40 ? 'high' : 'low'}`}>
                      Risk Score: {scanResult.riskScore}/100
                    </div>
                  </div>

                  <div className="results-summary">
                    <div className="summary-card">
                      <Fingerprint size={24} />
                      <div>
                        <h4>{scanResult.findings.length}</h4>
                        <p>PII Items Found</p>
                      </div>
                    </div>
                    <div className="summary-card">
                      <Key size={24} />
                      <div>
                        <h4>{scanResult.keywords.length}</h4>
                        <p>Sensitive Keywords</p>
                      </div>
                    </div>
                    <div className="summary-card">
                      <Scale size={24} />
                      <div>
                        <h4>{scanResult.complianceImpact.length}</h4>
                        <p>Compliance Standards</p>
                      </div>
                    </div>
                  </div>

                  {scanResult.findings.length > 0 && (
                    <div className="findings-list">
                      <h4>🔒 Detected PII Items</h4>
                      {scanResult.findings.map((finding, index) => (
                        <motion.div
                          key={index}
                          className="finding-card"
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: index * 0.05 }}
                        >
                          <div className="finding-header">
                            <div className="finding-type">
                              {getCategoryIcon(finding.category)}
                              <span>{finding.name}</span>
                            </div>
                            <div className="finding-severity" style={{ backgroundColor: getSeverityColor(finding.severity) }}>
                              {getSeverityIcon(finding.severity)}
                              {finding.severity}
                            </div>
                          </div>
                          <div className="finding-details">
                            <div className="detail-row">
                              <span className="label">Value:</span>
                              <code>{finding.value}</code>
                            </div>
                            <div className="detail-row">
                              <span className="label">Category:</span>
                              <span>{finding.category}</span>
                            </div>
                            <div className="detail-row">
                              <span className="label">Compliance:</span>
                              <div className="compliance-tags">
                                {finding.compliance.map((std, i) => (
                                  <span key={i} className="compliance-tag">{std}</span>
                                ))}
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      ))}
                    </div>
                  )}

                  {scanResult.recommendations.length > 0 && (
                    <div className="recommendations">
                      <h4>💡 Recommendations</h4>
                      <ul>
                        {scanResult.recommendations.map((rec, index) => (
                          <li key={index}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </motion.div>
              )}

              {/* PII Detection Capabilities */}
              <div className="capabilities-section">
                <h3>🛡️ Detection Capabilities</h3>
                <div className="pii-types-grid">
                  {Object.entries(PII_PATTERNS).map(([key, pattern]) => (
                    <div key={key} className="pii-type-card">
                      <div className="pii-header">
                        {getCategoryIcon(pattern.category)}
                        <h4>{pattern.name}</h4>
                      </div>
                      <div className="pii-meta">
                        <span className={`severity-badge ${pattern.severity}`}>
                          {pattern.severity}
                        </span>
                        <span className="category-badge">{pattern.category}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Data Leak Prevention Tab */}
          {activeTab === 1 && (
            <div className="dlp-content">
              <div className="section-header">
                <ShieldAlert size={24} />
                <h2>Data Leak Prevention (DLP)</h2>
              </div>

              <div className="info-card">
                <h3>Real-Time Leak Detection</h3>
                <p>
                  Monitors clipboard, file sharing, and email for sensitive data leaks. 
                  Automatically blocks transmission of critical PII based on configurable policies.
                </p>
              </div>

              <div className="dlp-controls">
                <h3>Test Leak Detection</h3>
                <div className="leak-test-buttons">
                  <motion.button
                    className="leak-test-btn clipboard"
                    onClick={() => simulateDataLeak('clipboard')}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Copy size={20} />
                    Test Clipboard Leak
                  </motion.button>

                  <motion.button
                    className="leak-test-btn file-share"
                    onClick={() => simulateDataLeak('file-share')}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Upload size={20} />
                    Test File Share Leak
                  </motion.button>

                  <motion.button
                    className="leak-test-btn email"
                    onClick={() => simulateDataLeak('email')}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Mail size={20} />
                    Test Email Leak
                  </motion.button>
                </div>
              </div>

              <div className="leak-alerts">
                <h3>Data Leak Alerts ({dataLeakAlerts.length})</h3>
                {dataLeakAlerts.length === 0 ? (
                  <div className="empty-state">
                    <CheckCircle2 size={48} />
                    <p>No data leaks detected</p>
                  </div>
                ) : (
                  dataLeakAlerts.map((alert) => (
                    <motion.div
                      key={alert.id}
                      className={`leak-alert ${alert.blocked ? 'blocked' : 'warned'}`}
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                    >
                      <div className="alert-header">
                        <div className={`alert-severity ${alert.severity}`}>
                          {alert.blocked ? <Lock size={18} /> : <Unlock size={18} />}
                          {alert.severity.toUpperCase()}
                        </div>
                        <h4>Data Leak via {alert.source}</h4>
                        <span className={`status-badge ${alert.blocked ? 'blocked' : 'warned'}`}>
                          {alert.blocked ? 'BLOCKED' : 'WARNING'}
                        </span>
                      </div>
                      <div className="alert-details">
                        <div className="detail-row">
                          <span className="label">PII Detected:</span>
                          <span className="value">{alert.piiDetected} items</span>
                        </div>
                        <div className="detail-row">
                          <span className="label">Types:</span>
                          <span className="value">{alert.piiTypes.join(', ')}</span>
                        </div>
                        <div className="detail-row">
                          <span className="label">Risk Score:</span>
                          <span className="value">{alert.riskScore}/100</span>
                        </div>
                        <div className="detail-row">
                          <span className="label">Time:</span>
                          <span className="value">{new Date(alert.timestamp).toLocaleString()}</span>
                        </div>
                      </div>
                    </motion.div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Compliance Reports Tab */}
          {activeTab === 2 && (
            <div className="compliance-content">
              <div className="section-header">
                <Scale size={24} />
                <h2>Compliance Reporting</h2>
              </div>

              <div className="compliance-controls">
                <div className="standard-selector">
                  <label>Select Compliance Standard:</label>
                  <select 
                    value={selectedStandard} 
                    onChange={(e) => setSelectedStandard(e.target.value)}
                    className="standard-select"
                  >
                    <option value="GDPR">GDPR (EU General Data Protection Regulation)</option>
                    <option value="CCPA">CCPA (California Consumer Privacy Act)</option>
                    <option value="HIPAA">HIPAA (Health Insurance Portability)</option>
                    <option value="PCI-DSS">PCI-DSS (Payment Card Industry)</option>
                  </select>
                </div>

                <motion.button
                  className="btn-primary"
                  onClick={generateCompliance}
                  disabled={!scanResult}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <FileText size={18} />
                  Generate {selectedStandard} Report
                </motion.button>
              </div>

              {complianceReport && (
                <motion.div
                  className="compliance-report"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                >
                  <div className="report-header">
                    <h3>📋 {complianceReport.standard} Compliance Report</h3>
                    <span className="report-date">
                      {new Date(complianceReport.generatedAt).toLocaleString()}
                    </span>
                  </div>

                  <div className="report-summary">
                    <div className="summary-stat">
                      <h4>{complianceReport.summary.totalFindings}</h4>
                      <p>Total Findings</p>
                    </div>
                    <div className="summary-stat critical">
                      <h4>{complianceReport.summary.criticalFindings}</h4>
                      <p>Critical Issues</p>
                    </div>
                    <div className="summary-stat high">
                      <h4>{complianceReport.summary.highFindings}</h4>
                      <p>High Priority</p>
                    </div>
                  </div>

                  <div className="compliance-status">
                    <h4>Compliance Status</h4>
                    <div className={`status-indicator ${complianceReport.complianceStatus.status}`}>
                      {complianceReport.complianceStatus.status === 'compliant' ? (
                        <CheckCircle2 size={24} />
                      ) : (
                        <XCircle size={24} />
                      )}
                      <span>{complianceReport.complianceStatus.status.toUpperCase()}</span>
                    </div>
                  </div>

                  <div className="risk-assessment">
                    <h4>Risk Assessment</h4>
                    <div className="risk-grid">
                      <div className="risk-item">
                        <span className="label">Overall Risk:</span>
                        <span className={`risk-value ${complianceReport.riskAssessment.overallRisk > 70 ? 'high' : 'medium'}`}>
                          {complianceReport.riskAssessment.overallRisk}/100
                        </span>
                      </div>
                      <div className="risk-item">
                        <span className="label">Data Breach Risk:</span>
                        <span className={`risk-badge ${complianceReport.riskAssessment.dataBreachRisk}`}>
                          {complianceReport.riskAssessment.dataBreachRisk}
                        </span>
                      </div>
                      <div className="risk-item">
                        <span className="label">Regulatory Risk:</span>
                        <span className={`risk-badge ${complianceReport.riskAssessment.regulatoryRisk}`}>
                          {complianceReport.riskAssessment.regulatoryRisk}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="compliance-recommendations">
                    <h4>📌 Compliance Recommendations</h4>
                    <ul>
                      {complianceReport.recommendations.map((rec, index) => (
                        <li key={index}>{rec}</li>
                      ))}
                    </ul>
                  </div>
                </motion.div>
              )}

              {/* Compliance Standards Info */}
              <div className="standards-info">
                <h3>Supported Compliance Standards</h3>
                <div className="standards-grid">
                  <div className="standard-card">
                    <h4>🇪🇺 GDPR</h4>
                    <p>EU General Data Protection Regulation - Protects personal data of EU citizens</p>
                    <span className="coverage">Coverage: Identity, Contact, Location, Biometric</span>
                  </div>
                  <div className="standard-card">
                    <h4>🇺🇸 CCPA</h4>
                    <p>California Consumer Privacy Act - Privacy rights for California residents</p>
                    <span className="coverage">Coverage: Identity, Contact, Financial, Behavioral</span>
                  </div>
                  <div className="standard-card">
                    <h4>🏥 HIPAA</h4>
                    <p>Health Insurance Portability - Protected Health Information (PHI)</p>
                    <span className="coverage">Coverage: Medical Records, Health Data, Insurance</span>
                  </div>
                  <div className="standard-card">
                    <h4>💳 PCI-DSS</h4>
                    <p>Payment Card Industry - Security for credit card transactions</p>
                    <span className="coverage">Coverage: Card Numbers, CVV, Payment Data</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* GDPR Tools Tab */}
          {activeTab === 3 && (
            <div className="gdpr-tools-content">
              <div className="section-header">
                <Shield size={24} />
                <h2>GDPR Compliance Tools</h2>
                <p>Data Subject Rights & Privacy Management</p>
              </div>

              {/* GDPR Actions */}
              <div className="gdpr-actions-grid">
                <motion.div className="gdpr-action-card" whileHover={{ scale: 1.02 }}>
                  <div className="action-icon blue">
                    <FileText size={32} />
                  </div>
                  <h3>Data Subject Access Request (DSAR)</h3>
                  <p>Generate comprehensive report of all personal data stored</p>
                  <span className="compliance-badge">Article 15</span>
                </motion.div>

                <motion.div className="gdpr-action-card" whileHover={{ scale: 1.02 }}>
                  <div className="action-icon green">
                    <Download size={32} />
                  </div>
                  <h3>Right to Data Portability</h3>
                  <p>Export personal data in machine-readable format</p>
                  <span className="compliance-badge">Article 20</span>
                </motion.div>

                <motion.div className="gdpr-action-card" whileHover={{ scale: 1.02 }}>
                  <div className="action-icon red">
                    <Trash2 size={32} />
                  </div>
                  <h3>Right to be Forgotten</h3>
                  <p>Permanently delete all personal data from systems</p>
                  <span className="compliance-badge">Article 17</span>
                </motion.div>

                <motion.div className="gdpr-action-card" whileHover={{ scale: 1.02 }}>
                  <div className="action-icon purple">
                    <Database size={32} />
                  </div>
                  <h3>Data Retention Policy</h3>
                  <p>Automatically delete data exceeding retention period</p>
                  <span className="compliance-badge">Article 5(1)(e)</span>
                </motion.div>
              </div>

              {/* GDPR Action Panel */}
              <div className="gdpr-action-panel">
                <h3>Execute GDPR Rights</h3>
                
                <div className="form-group">
                  <label>Select Action:</label>
                  <select 
                    value={gdprAction} 
                    onChange={(e) => setGdprAction(e.target.value)}
                    className="form-control"
                  >
                    <option value="dsar">Data Subject Access Request (DSAR)</option>
                    <option value="export">Export Personal Data (Portability)</option>
                    <option value="forget">Right to be Forgotten</option>
                    <option value="retention">Apply Retention Policy</option>
                  </select>
                </div>

                <div className="form-group">
                  <label>Identifier (Email, User ID, etc.):</label>
                  <input
                    type="text"
                    value={gdprIdentifier}
                    onChange={(e) => setGdprIdentifier(e.target.value)}
                    placeholder="user@example.com or USER12345"
                    className="form-control"
                  />
                </div>

                {gdprAction === 'retention' && (
                  <div className="form-group">
                    <label>Retention Period (Days):</label>
                    <input
                      type="number"
                      value={retentionDays}
                      onChange={(e) => setRetentionDays(parseInt(e.target.value))}
                      min="30"
                      max="3650"
                      className="form-control"
                    />
                    <small>Data older than {retentionDays} days will be deleted</small>
                  </div>
                )}

                <div className="button-group">
                  <button 
                    onClick={handleGDPRAction}
                    className="btn btn-primary"
                  >
                    <Shield size={18} />
                    Execute {gdprAction === 'dsar' ? 'DSAR' : gdprAction === 'export' ? 'Export' : gdprAction === 'forget' ? 'Deletion' : 'Retention Policy'}
                  </button>

                  {gdprResult && (
                    <button 
                      onClick={downloadGDPRReport}
                      className="btn btn-success"
                    >
                      <Download size={18} />
                      Download Report
                    </button>
                  )}
                </div>
              </div>

              {/* GDPR Result Display */}
              {gdprResult && (
                <motion.div 
                  className="gdpr-result-panel"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                >
                  <h3>
                    {gdprAction === 'dsar' && '📋 DSAR Report Generated'}
                    {gdprAction === 'export' && '📦 Data Export Completed'}
                    {gdprAction === 'forget' && '🗑️ Data Deletion Completed'}
                    {gdprAction === 'retention' && '⏰ Retention Policy Applied'}
                  </h3>
                  
                  <pre className="result-json">
                    {JSON.stringify(gdprResult, null, 2)}
                  </pre>

                  {gdprAction === 'forget' && gdprResult.itemsDeleted && (
                    <div className="deletion-summary">
                      <h4>Items Permanently Deleted:</h4>
                      <ul>
                        <li>Scan History: {gdprResult.itemsDeleted.scanHistory}</li>
                        <li>Leak Alerts: {gdprResult.itemsDeleted.leakAlerts}</li>
                        <li>Vault Items: {gdprResult.itemsDeleted.vaultItems}</li>
                        <li>Compliance Reports: {gdprResult.itemsDeleted.complianceReports}</li>
                      </ul>
                      <p className="warning-text">⚠️ This action is irreversible!</p>
                    </div>
                  )}

                  {gdprAction === 'dsar' && gdprResult.summary && (
                    <div className="dsar-summary">
                      <h4>DSAR Summary:</h4>
                      <p>Total Data Points: <strong>{gdprResult.summary.totalDataPoints}</strong></p>
                      <p>Categories Found: <strong>{gdprResult.summary.categories.join(', ')}</strong></p>
                      <div className="rights-list">
                        <h5>Available Rights:</h5>
                        <ul>
                          {gdprResult.summary.rights.map((right, idx) => (
                            <li key={idx}><CheckCircle2 size={16} /> {right}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}
                </motion.div>
              )}

              {/* Data Anonymization Tool */}
              <div className="anonymization-panel">
                <h3>🎭 Data Anonymization & Pseudonymization</h3>
                <p>Remove personally identifiable information while preserving data utility</p>

                <div className="form-group">
                  <label>Text to Anonymize:</label>
                  <textarea
                    value={scanText}
                    onChange={(e) => setScanText(e.target.value)}
                    placeholder="Enter text containing PII..."
                    rows="6"
                    className="form-control"
                  />
                </div>

                <button 
                  onClick={handleAnonymizeText}
                  className="btn btn-secondary"
                >
                  <EyeOff size={18} />
                  Anonymize Data
                </button>

                {anonymizedText && (
                  <motion.div 
                    className="anonymized-result"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                  >
                    <h4>✅ Anonymized Text:</h4>
                    <div className="result-box">
                      {anonymizedText}
                    </div>
                    <p className="info-text">
                      All PII has been replaced with generic placeholders. 
                      This data cannot be reversed and is GDPR-compliant.
                    </p>
                  </motion.div>
                )}
              </div>

              {/* GDPR Compliance Info */}
              <div className="gdpr-info-panel">
                <h3>📚 GDPR Compliance Reference</h3>
                <div className="compliance-grid">
                  <div className="compliance-item">
                    <h4>Article 5</h4>
                    <p>Principles relating to processing of personal data</p>
                  </div>
                  <div className="compliance-item">
                    <h4>Article 15</h4>
                    <p>Right of access by the data subject</p>
                  </div>
                  <div className="compliance-item">
                    <h4>Article 17</h4>
                    <p>Right to erasure ('right to be forgotten')</p>
                  </div>
                  <div className="compliance-item">
                    <h4>Article 20</h4>
                    <p>Right to data portability</p>
                  </div>
                  <div className="compliance-item">
                    <h4>Article 25</h4>
                    <p>Data protection by design and by default</p>
                  </div>
                  <div className="compliance-item">
                    <h4>Article 33</h4>
                    <p>Notification of personal data breach</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Statistics Tab */}
          {activeTab === 4 && (
            <div className="statistics-content">
              <div className="section-header">
                <Activity size={24} />
                <h2>Data Protection Statistics</h2>
              </div>

              <div className="stats-grid-large">
                <motion.div className="stat-card-large" whileHover={{ y: -5 }}>
                  <div className="stat-icon blue">
                    <Search size={32} />
                  </div>
                  <div className="stat-content">
                    <h3>{statistics.totalScans}</h3>
                    <p>Total Scans Performed</p>
                  </div>
                </motion.div>

                <motion.div className="stat-card-large" whileHover={{ y: -5 }}>
                  <div className="stat-icon orange">
                    <ShieldAlert size={32} />
                  </div>
                  <div className="stat-content">
                    <h3>{statistics.totalLeakAlerts}</h3>
                    <p>Data Leak Alerts</p>
                  </div>
                </motion.div>

                <motion.div className="stat-card-large" whileHover={{ y: -5 }}>
                  <div className="stat-icon red">
                    <AlertTriangle size={32} />
                  </div>
                  <div className="stat-content">
                    <h3>{statistics.criticalLeaks}</h3>
                    <p>Critical Leaks Blocked</p>
                  </div>
                </motion.div>

                <motion.div className="stat-card-large" whileHover={{ y: -5 }}>
                  <div className="stat-icon purple">
                    <Lock size={32} />
                  </div>
                  <div className="stat-content">
                    <h3>{statistics.encryptedItems}</h3>
                    <p>Encrypted Items</p>
                  </div>
                </motion.div>

                <motion.div className="stat-card-large" whileHover={{ y: -5 }}>
                  <div className="stat-icon green">
                    <FileCheck size={32} />
                  </div>
                  <div className="stat-content">
                    <h3>{statistics.complianceReports}</h3>
                    <p>Compliance Reports</p>
                  </div>
                </motion.div>

                <motion.div className="stat-card-large" whileHover={{ y: -5 }}>
                  <div className="stat-icon yellow">
                    <Activity size={32} />
                  </div>
                  <div className="stat-content">
                    <h3>{statistics.averageRiskScore.toFixed(1)}</h3>
                    <p>Average Risk Score</p>
                  </div>
                </motion.div>
              </div>

              <div className="protected-data-info">
                <h3>🛡️ What We Protect</h3>
                <div className="protection-grid">
                  <div className="protection-item">
                    <CreditCard size={24} />
                    <h4>Financial Data</h4>
                    <p>Credit cards, bank accounts, tax IDs</p>
                  </div>
                  <div className="protection-item">
                    <Fingerprint size={24} />
                    <h4>Identity Information</h4>
                    <p>SSN, passports, driver's licenses</p>
                  </div>
                  <div className="protection-item">
                    <Mail size={24} />
                    <h4>Contact Details</h4>
                    <p>Email addresses, phone numbers</p>
                  </div>
                  <div className="protection-item">
                    <Activity size={24} />
                    <h4>Health Records</h4>
                    <p>Medical records, patient IDs, diagnoses</p>
                  </div>
                  <div className="protection-item">
                    <Key size={24} />
                    <h4>Credentials</h4>
                    <p>Passwords, API keys, tokens</p>
                  </div>
                  <div className="protection-item">
                    <MapPin size={24} />
                    <h4>Location Data</h4>
                    <p>Physical addresses, GPS coordinates</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
};

export default DataProtection;
