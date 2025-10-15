import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle,
  Download,
  Clock,
  HardDrive,
  RefreshCw,
  Settings,
  Archive,
  Play,
  Pause,
  Trash2,
  Calendar,
  Bell,
  Info,
  XCircle,
  ChevronDown,
  ChevronRight,
  Cpu,
  Wifi,
  Volume2,
  Bluetooth,
  Database
} from 'lucide-react';
import {
  scanDrivers,
  updateDriver,
  getBackupManager,
  getScheduler,
  getUpdateRecommendations,
  runHardwareDiagnostics,
  getRestorePointAdvice
} from '../services/enhancedDriverScanner';
import './EnhancedDriverScanner.css';

const EnhancedDriverScanner = () => {
  const [activeTab, setActiveTab] = useState('scan');
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [expandedDriver, setExpandedDriver] = useState(null);
  const [updating, setUpdating] = useState({});
  const [backups, setBackups] = useState([]);
  const [schedule, setSchedule] = useState(null);
  const [diagnostics, setDiagnostics] = useState(null);
  const [runningDiagnostics, setRunningDiagnostics] = useState(false);
  const [notification, setNotification] = useState(null);
  const [downloadProgress, setDownloadProgress] = useState({});
  const [installDialog, setInstallDialog] = useState(null);
  const [downloadedDrivers, setDownloadedDrivers] = useState({});

  const backupManager = getBackupManager();
  const scheduler = getScheduler();

  useEffect(() => {
    setBackups(backupManager.backups);
    setSchedule(scheduler.schedule);
  }, []);

  useEffect(() => {
    if (activeTab === 'scan') {
      performScan();
    }
  }, [activeTab]);

  const performScan = async () => {
    setScanning(true);
    setScanResults(null);
    
    try {
      const results = await scanDrivers();
      setScanResults(results);
      
      showNotification(
        `Scan complete: ${results.totalDrivers} drivers found, ${results.updatesAvailable} updates available`,
        'success'
      );
    } catch (error) {
      showNotification('Scan failed: ' + error.message, 'error');
    } finally {
      setScanning(false);
    }
  };

  const handleDownloadDriver = async (driver) => {
    setDownloadProgress(prev => ({ ...prev, [driver.id]: 0 }));
    
    try {
      // Simulate download with progress
      for (let i = 0; i <= 100; i += 10) {
        await new Promise(resolve => setTimeout(resolve, 200));
        setDownloadProgress(prev => ({ ...prev, [driver.id]: i }));
      }
      
      setDownloadedDrivers(prev => ({ ...prev, [driver.id]: true }));
      setDownloadProgress(prev => ({ ...prev, [driver.id]: undefined }));
      
      // Show install dialog
      setInstallDialog({
        driver,
        downloadedSize: driver.updateSize || '0 MB',
        version: driver.latestVersion || 'Unknown'
      });
      
      showNotification(`${driver.name} downloaded successfully`, 'success');
    } catch (error) {
      setDownloadProgress(prev => ({ ...prev, [driver.id]: undefined }));
      showNotification('Download failed: ' + error.message, 'error');
    }
  };

  const handleInstallDriver = async (driver) => {
    setInstallDialog(null);
    setUpdating(prev => ({ ...prev, [driver.id]: true }));
    
    try {
      const result = await updateDriver(driver.id, schedule?.createBackup !== false);
      
      if (result.backup) {
        setBackups(backupManager.backups);
      }
      
      setDownloadedDrivers(prev => ({ ...prev, [driver.id]: false }));
      showNotification(result.message, 'success');
      performScan(); // Refresh scan
    } catch (error) {
      showNotification('Installation failed: ' + error.message, 'error');
    } finally {
      setUpdating(prev => ({ ...prev, [driver.id]: false }));
    }
  };

  const handleUpdate = async (driver) => {
    // Start download process
    await handleDownloadDriver(driver);
  };

  const handleRestore = async (backup) => {
    try {
      const result = await backupManager.restoreBackup(backup.id);
      showNotification(result.message, 'success');
      performScan();
    } catch (error) {
      showNotification('Restore failed: ' + error.message, 'error');
    }
  };

  const handleDeleteBackup = (backupId) => {
    backupManager.deleteBackup(backupId);
    setBackups(backupManager.backups);
    showNotification('Backup deleted', 'info');
  };

  const updateScheduleSettings = (updates) => {
    const newSchedule = scheduler.updateSchedule(updates);
    setSchedule(newSchedule);
    showNotification('Schedule updated', 'success');
  };

  const runDiagnostics = async (driver) => {
    setRunningDiagnostics(true);
    setDiagnostics(null);
    
    try {
      const result = await runHardwareDiagnostics(driver);
      setDiagnostics(result);
    } catch (error) {
      showNotification('Diagnostics failed: ' + error.message, 'error');
    } finally {
      setRunningDiagnostics(false);
    }
  };

  const showNotification = (message, type = 'info') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 5000);
  };

  const getCategoryIcon = (category) => {
    switch (category) {
      case 'Graphics': return <Cpu className="category-icon" />;
      case 'Network': return <Wifi className="category-icon" />;
      case 'Audio': return <Volume2 className="category-icon" />;
      case 'Bluetooth': return <Bluetooth className="category-icon" />;
      case 'Storage': return <Database className="category-icon" />;
      default: return <HardDrive className="category-icon" />;
    }
  };

  const getPriorityBadge = (priority) => {
    const badges = {
      critical: { label: 'CRITICAL', className: 'priority-critical' },
      high: { label: 'HIGH', className: 'priority-high' },
      recommended: { label: 'RECOMMENDED', className: 'priority-recommended' },
      none: { label: 'UP TO DATE', className: 'priority-none' }
    };
    
    const badge = badges[priority] || badges.none;
    
    return (
      <span className={`priority-badge ${badge.className}`}>
        {badge.label}
      </span>
    );
  };

  return (
    <div className="enhanced-driver-scanner">
      <div className="scanner-header">
        <div className="header-content">
          <div className="header-icon">
            <Shield size={32} />
          </div>
          <div className="header-text">
            <h1>Advanced Driver Manager</h1>
            <p>Automated driver updates with backup & diagnostics</p>
          </div>
        </div>

        {scanResults && (
          <div className="quick-stats">
            <div className="stat-item">
              <HardDrive size={16} />
              <span>{scanResults.totalDrivers} Drivers</span>
            </div>
            <div className="stat-item stat-success">
              <CheckCircle size={16} />
              <span>{scanResults.upToDate} Up-to-date</span>
            </div>
            {scanResults.updatesAvailable > 0 && (
              <div className="stat-item stat-warning">
                <Download size={16} />
                <span>{scanResults.updatesAvailable} Updates</span>
              </div>
            )}
            {scanResults.criticalUpdates > 0 && (
              <div className="stat-item stat-critical">
                <AlertTriangle size={16} />
                <span>{scanResults.criticalUpdates} Critical</span>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="scanner-tabs">
        {[
          { id: 'scan', label: 'Driver Scan', icon: Activity },
          { id: 'backups', label: 'Backups', icon: Archive },
          { id: 'schedule', label: 'Auto-Update', icon: Calendar },
          { id: 'diagnostics', label: 'Diagnostics', icon: Settings }
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

      {/* Installation Confirmation Dialog */}
      <AnimatePresence>
        {installDialog && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setInstallDialog(null)}
          >
            <motion.div
              className="install-dialog"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="dialog-header">
                <Download className="dialog-icon" size={32} />
                <h3>Install Driver Update</h3>
              </div>
              
              <div className="dialog-content">
                <div className="driver-install-info">
                  <div className="info-row">
                    <span className="info-label">Driver:</span>
                    <span className="info-value">{installDialog.driver.name}</span>
                  </div>
                  <div className="info-row">
                    <span className="info-label">Version:</span>
                    <span className="info-value">{installDialog.version}</span>
                  </div>
                  <div className="info-row">
                    <span className="info-label">Size:</span>
                    <span className="info-value">{installDialog.downloadedSize}</span>
                  </div>
                  <div className="info-row">
                    <span className="info-label">Manufacturer:</span>
                    <span className="info-value">{installDialog.driver.manufacturer}</span>
                  </div>
                </div>

                <div className="install-warning">
                  <AlertTriangle size={20} />
                  <div>
                    <p><strong>Important:</strong></p>
                    <ul>
                      <li>Close all running applications before installation</li>
                      <li>A system restart will be required after installation</li>
                      {schedule?.createBackup !== false && (
                        <li>A backup of your current driver will be created automatically</li>
                      )}
                    </ul>
                  </div>
                </div>
              </div>
              
              <div className="dialog-actions">
                <button
                  className="dialog-button dialog-cancel"
                  onClick={() => setInstallDialog(null)}
                >
                  Cancel
                </button>
                <button
                  className="dialog-button dialog-install"
                  onClick={() => handleInstallDriver(installDialog.driver)}
                >
                  <Play size={16} />
                  Install Now
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="scanner-content">
        <AnimatePresence mode="wait">
          {activeTab === 'scan' && (
            <motion.div
              key="scan"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="tab-content"
            >
              <div className="scan-controls">
                <button
                  className="scan-button"
                  onClick={performScan}
                  disabled={scanning}
                >
                  <RefreshCw size={18} className={scanning ? 'spinning' : ''} />
                  <span>{scanning ? 'Scanning...' : 'Scan Drivers'}</span>
                </button>

                {scanResults && (
                  <div className="scan-info">
                    <Info size={16} />
                    <span>Last scanned: {new Date().toLocaleString()}</span>
                  </div>
                )}
              </div>

              {scanning && (
                <div className="scanning-animation">
                  <motion.div
                    className="scan-wave"
                    animate={{ scale: [1, 1.5, 1], opacity: [0.5, 0, 0.5] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  />
                  <Activity size={48} />
                  <p>Scanning hardware and drivers...</p>
                </div>
              )}

              {scanResults && !scanning && (
                <>
                  {getUpdateRecommendations(scanResults.results).length > 0 && (
                    <div className="recommendations-section">
                      <h3>
                        <AlertTriangle size={20} />
                        Update Recommendations
                      </h3>
                      
                      {getUpdateRecommendations(scanResults.results).map((rec, idx) => (
                        <div key={idx} className={`recommendation recommendation-${rec.priority}`}>
                          <div className="rec-header">
                            <h4>{rec.title}</h4>
                            <span className="rec-action">{rec.action}</span>
                          </div>
                          <p>{rec.description}</p>
                          <div className="rec-drivers">
                            {rec.drivers.slice(0, 3).map(d => (
                              <div key={d.id} className="rec-driver-item">
                                {getCategoryIcon(d.category)}
                                <span>{d.name}</span>
                                <span className="version-badge">
                                  {d.currentVersion} → {d.latestVersion}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="drivers-list">
                    <h3>
                      <HardDrive size={20} />
                      All Drivers ({scanResults.totalDrivers})
                    </h3>

                    {scanResults.results.map(driver => (
                      <div key={driver.id} className="driver-card">
                        <div
                          className="driver-header"
                          onClick={() => setExpandedDriver(expandedDriver === driver.id ? null : driver.id)}
                        >
                          <div className="driver-main-info">
                            {getCategoryIcon(driver.category)}
                            <div className="driver-name-section">
                              <h4>{driver.name}</h4>
                              <span className="driver-category">{driver.category} • {driver.manufacturer}</span>
                            </div>
                          </div>

                          <div className="driver-status-section">
                            {getPriorityBadge(driver.updatePriority)}
                            
                            <div className="driver-version">
                              <span className="current-version">{driver.currentVersion}</span>
                              {driver.status === 'update-available' && (
                                <>
                                  <ChevronRight size={14} className="version-arrow" />
                                  <span className="latest-version">{driver.latestVersion}</span>
                                </>
                              )}
                            </div>

                            <button className="expand-button">
                              {expandedDriver === driver.id ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
                            </button>
                          </div>
                        </div>

                        <AnimatePresence>
                          {expandedDriver === driver.id && (
                            <motion.div
                              initial={{ height: 0, opacity: 0 }}
                              animate={{ height: 'auto', opacity: 1 }}
                              exit={{ height: 0, opacity: 0 }}
                              className="driver-details"
                            >
                              {driver.hasVulnerability && driver.vulnerability && (
                                <div className="vulnerability-alert">
                                  <div className="vuln-header">
                                    <AlertTriangle size={20} />
                                    <h5>Security Vulnerability Detected</h5>
                                    <span className={`severity-badge severity-${driver.vulnerability.severity.toLowerCase()}`}>
                                      {driver.vulnerability.severity}
                                    </span>
                                  </div>
                                  <div className="vuln-info">
                                    <p><strong>{driver.vulnerability.cve}</strong></p>
                                    <p>{driver.vulnerability.description}</p>
                                    <div className="vuln-meta">
                                      <span>CVSS Score: {driver.vulnerability.cvssScore}</span>
                                      <span>Published: {driver.vulnerability.published}</span>
                                      {driver.vulnerability.exploitAvailable && (
                                        <span className="exploit-badge">Exploit Available</span>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              )}

                              <div className="driver-metadata">
                                <div className="metadata-grid">
                                  <div className="metadata-item">
                                    <label>Hardware ID</label>
                                    <span>{driver.hardwareId}</span>
                                  </div>
                                  <div className="metadata-item">
                                    <label>Driver Provider</label>
                                    <span>{driver.driverProvider}</span>
                                  </div>
                                  <div className="metadata-item">
                                    <label>Driver Date</label>
                                    <span>{driver.driverDate}</span>
                                  </div>
                                  <div className="metadata-item">
                                    <label>Installed</label>
                                    <span>{driver.installedDate}</span>
                                  </div>
                                  <div className="metadata-item">
                                    <label>Device Class</label>
                                    <span>{driver.deviceClass}</span>
                                  </div>
                                  <div className="metadata-item">
                                    <label>Status</label>
                                    <span className="status-working">{driver.status}</span>
                                  </div>
                                </div>

                                {driver.latestInfo && (
                                  <div className="update-info">
                                    <h5>Update Information</h5>
                                    <p><strong>Version {driver.latestVersion}</strong> • {driver.latestInfo.released}</p>
                                    <p>{driver.latestInfo.releaseNotes}</p>
                                    <div className="update-meta">
                                      <span>Size: {driver.updateSize}</span>
                                      <span>Stability: {driver.stability}</span>
                                      {driver.latestInfo.recommended && (
                                        <span className="recommended-badge">Recommended</span>
                                      )}
                                    </div>
                                  </div>
                                )}
                              </div>

                              <div className="driver-actions">
                                {driver.status === 'update-available' && (
                                  downloadProgress[driver.id] !== undefined ? (
                                    <div className="download-progress-container">
                                      <div className="progress-bar">
                                        <div 
                                          className="progress-fill"
                                          style={{ width: `${downloadProgress[driver.id]}%` }}
                                        />
                                      </div>
                                      <span className="progress-text">
                                        Downloading... {downloadProgress[driver.id]}%
                                      </span>
                                    </div>
                                  ) : downloadedDrivers[driver.id] ? (
                                    <button
                                      className="action-button action-install"
                                      onClick={() => setInstallDialog({ 
                                        driver,
                                        downloadedSize: driver.updateSize || '0 MB',
                                        version: driver.latestVersion || 'Unknown'
                                      })}
                                      disabled={updating[driver.id]}
                                    >
                                      <Play size={16} />
                                      <span>{updating[driver.id] ? 'Installing...' : 'Install Now'}</span>
                                    </button>
                                  ) : (
                                    <button
                                      className="action-button action-update"
                                      onClick={() => handleUpdate(driver)}
                                      disabled={updating[driver.id]}
                                    >
                                      <Download size={16} />
                                      <span>Download Update</span>
                                    </button>
                                  )
                                )}
                                
                                <button
                                  className="action-button action-secondary"
                                  onClick={() => runDiagnostics(driver)}
                                  disabled={runningDiagnostics}
                                >
                                  <Activity size={16} />
                                  <span>Run Diagnostics</span>
                                </button>

                                {driver.downloadUrl && (
                                  <a
                                    href={driver.downloadUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="action-button action-secondary"
                                  >
                                    <Download size={16} />
                                    <span>Download Manually</span>
                                  </a>
                                )}
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </motion.div>
          )}

          {activeTab === 'backups' && (
            <motion.div
              key="backups"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="tab-content"
            >
              <div className="backups-header">
                <h3>
                  <Archive size={20} />
                  Driver Backups ({backups.length})
                </h3>
                <p>Restore previous driver versions if issues occur</p>
              </div>

              {backups.length === 0 ? (
                <div className="empty-state">
                  <Archive size={48} />
                  <h4>No Backups Yet</h4>
                  <p>Backups are automatically created when you update drivers</p>
                </div>
              ) : (
                <div className="backups-list">
                  {backups.map(backup => (
                    <div key={backup.id} className="backup-card">
                      <div className="backup-icon">
                        {getCategoryIcon(backup.category)}
                      </div>
                      
                      <div className="backup-info">
                        <h4>{backup.driverName}</h4>
                        <p className="backup-desc">{backup.description}</p>
                        <div className="backup-meta">
                          <span>
                            <Clock size={14} />
                            {new Date(backup.timestamp).toLocaleString()}
                          </span>
                          <span>Version {backup.version}</span>
                          <span>{backup.size}</span>
                        </div>
                      </div>

                      <div className="backup-actions">
                        <button
                          className="action-button action-restore"
                          onClick={() => handleRestore(backup)}
                        >
                          <RefreshCw size={16} />
                          <span>Restore</span>
                        </button>
                        <button
                          className="action-button action-danger"
                          onClick={() => handleDeleteBackup(backup.id)}
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>
          )}

          {activeTab === 'schedule' && schedule && (
            <motion.div
              key="schedule"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="tab-content"
            >
              <div className="schedule-header">
                <h3>
                  <Calendar size={20} />
                  Automatic Update Schedule
                </h3>
                <p>Configure automatic driver update checking and installation</p>
              </div>

              <div className="schedule-settings">
                <div className="setting-card">
                  <div className="setting-header">
                    <div className="setting-title">
                      <h4>Enable Auto-Updates</h4>
                      <p>Automatically check for driver updates</p>
                    </div>
                    <label className="toggle-switch">
                      <input
                        type="checkbox"
                        checked={schedule.enabled}
                        onChange={(e) => updateScheduleSettings({ enabled: e.target.checked })}
                      />
                      <span className="toggle-slider"></span>
                    </label>
                  </div>
                </div>

                {schedule.enabled && (
                  <>
                    <div className="setting-card">
                      <h4>Check Frequency</h4>
                      <div className="radio-group">
                        {['daily', 'weekly', 'monthly'].map(freq => (
                          <label key={freq} className="radio-label">
                            <input
                              type="radio"
                              name="frequency"
                              value={freq}
                              checked={schedule.frequency === freq}
                              onChange={(e) => updateScheduleSettings({ frequency: e.target.value })}
                            />
                            <span>{freq.charAt(0).toUpperCase() + freq.slice(1)}</span>
                          </label>
                        ))}
                      </div>
                    </div>

                    <div className="setting-card">
                      <h4>Check Time</h4>
                      <input
                        type="time"
                        className="time-input"
                        value={schedule.checkTime}
                        onChange={(e) => updateScheduleSettings({ checkTime: e.target.value })}
                      />
                      <p className="setting-help">
                        Next check: {scheduler.getNextCheckTime() ? 
                          new Date(scheduler.getNextCheckTime()).toLocaleString() : 
                          'Not scheduled'}
                      </p>
                    </div>

                    <div className="setting-card">
                      <div className="setting-header">
                        <div className="setting-title">
                          <h4>Auto-Install Updates</h4>
                          <p>Automatically install available updates</p>
                        </div>
                        <label className="toggle-switch">
                          <input
                            type="checkbox"
                            checked={schedule.autoInstall}
                            onChange={(e) => updateScheduleSettings({ autoInstall: e.target.checked })}
                          />
                          <span className="toggle-slider"></span>
                        </label>
                      </div>
                    </div>

                    <div className="setting-card">
                      <div className="setting-header">
                        <div className="setting-title">
                          <h4>Create Backups</h4>
                          <p>Create backup before updating</p>
                        </div>
                        <label className="toggle-switch">
                          <input
                            type="checkbox"
                            checked={schedule.createBackup}
                            onChange={(e) => updateScheduleSettings({ createBackup: e.target.checked })}
                          />
                          <span className="toggle-slider"></span>
                        </label>
                      </div>
                    </div>

                    <div className="setting-card">
                      <div className="setting-header">
                        <div className="setting-title">
                          <h4>Notify Only</h4>
                          <p>Show notification instead of auto-installing</p>
                        </div>
                        <label className="toggle-switch">
                          <input
                            type="checkbox"
                            checked={schedule.notifyOnly}
                            onChange={(e) => updateScheduleSettings({ notifyOnly: e.target.checked })}
                          />
                          <span className="toggle-slider"></span>
                        </label>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </motion.div>
          )}

          {activeTab === 'diagnostics' && (
            <motion.div
              key="diagnostics"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="tab-content"
            >
              <div className="diagnostics-header">
                <h3>
                  <Settings size={20} />
                  Hardware Diagnostics
                </h3>
                <p>Run comprehensive tests on your drivers and hardware</p>
              </div>

              {!diagnostics && !runningDiagnostics && scanResults && (
                <div className="diagnostics-select">
                  <h4>Select a driver to test:</h4>
                  <div className="driver-select-grid">
                    {scanResults.results.map(driver => (
                      <button
                        key={driver.id}
                        className="driver-select-card"
                        onClick={() => runDiagnostics(driver)}
                      >
                        {getCategoryIcon(driver.category)}
                        <span>{driver.name}</span>
                        <Play size={16} />
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {runningDiagnostics && (
                <div className="diagnostics-running">
                  <motion.div
                    className="diag-spinner"
                    animate={{ rotate: 360 }}
                    transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
                  >
                    <Settings size={48} />
                  </motion.div>
                  <h4>Running Diagnostics...</h4>
                  <p>Testing hardware functionality and performance</p>
                </div>
              )}

              {diagnostics && !runningDiagnostics && (
                <div className="diagnostics-results">
                  <div className="diag-header">
                    <div className="diag-title">
                      {getCategoryIcon(diagnostics.category)}
                      <div>
                        <h4>{diagnostics.driverName}</h4>
                        <span className="diag-timestamp">
                          {new Date(diagnostics.timestamp).toLocaleString()}
                        </span>
                      </div>
                    </div>
                    <div className={`diag-overall-status status-${diagnostics.overallStatus}`}>
                      <CheckCircle size={20} />
                      <span>{diagnostics.overallStatus.toUpperCase()}</span>
                    </div>
                  </div>

                  <div className="diag-tests">
                    {diagnostics.tests.map((test, idx) => (
                      <div key={idx} className={`diag-test test-${test.status}`}>
                        <div className="test-name">
                          {test.status === 'passed' ? <CheckCircle size={18} /> : <XCircle size={18} />}
                          <span>{test.name}</span>
                        </div>
                        <span className="test-details">{test.details}</span>
                      </div>
                    ))}
                  </div>

                  <button
                    className="action-button action-secondary"
                    onClick={() => setDiagnostics(null)}
                  >
                    <RefreshCw size={16} />
                    <span>Run Another Test</span>
                  </button>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};

export default EnhancedDriverScanner;
