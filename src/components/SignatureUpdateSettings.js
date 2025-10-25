import React, { useState, useEffect } from 'react';
import signatureUpdater from '../services/signatureUpdater';
import './SignatureUpdateSettings.css';

const SignatureUpdateSettings = () => {
  const [status, setStatus] = useState(null);
  const [updateHistory, setUpdateHistory] = useState([]);
  const [isUpdating, setIsUpdating] = useState(false);
  const [lastUpdateResult, setLastUpdateResult] = useState(null);
  const [config, setConfig] = useState({
    enableAutoUpdate: true,
    enableSilentUpdate: true,
    updateInterval: 3600000 // 1 hour
  });

  useEffect(() => {
    // Load initial status
    loadStatus();

    // Listen for update events
    signatureUpdater.on('updateStart', () => {
      setIsUpdating(true);
      setLastUpdateResult(null);
    });

    signatureUpdater.on('updateComplete', (result) => {
      setIsUpdating(false);
      setLastUpdateResult({ success: true, ...result });
      loadStatus();
    });

    signatureUpdater.on('updateFailed', (error) => {
      setIsUpdating(false);
      setLastUpdateResult({ success: false, ...error });
      loadStatus();
    });

    signatureUpdater.on('signaturesUpdated', (info) => {
      console.log('Signatures updated:', info);
      loadStatus();
    });

    // Cleanup listeners
    return () => {
      signatureUpdater.removeAllListeners();
    };
  }, []);

  const loadStatus = () => {
    const currentStatus = signatureUpdater.getStatus();
    setStatus(currentStatus);
    setUpdateHistory(signatureUpdater.getUpdateHistory());
    setConfig(currentStatus.config);
  };

  const handleForceUpdate = async () => {
    setIsUpdating(true);
    setLastUpdateResult(null);
    
    const result = await signatureUpdater.forceUpdate();
    
    setIsUpdating(false);
    setLastUpdateResult(result);
    loadStatus();
  };

  const handleConfigChange = (key, value) => {
    const newConfig = { ...config, [key]: value };
    setConfig(newConfig);
    signatureUpdater.configure(newConfig);
  };

  const formatInterval = (ms) => {
    const hours = ms / (1000 * 60 * 60);
    if (hours < 1) {
      return `${Math.round(ms / (1000 * 60))} minutes`;
    }
    return `${Math.round(hours)} ${hours === 1 ? 'hour' : 'hours'}`;
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const getStatusBadge = () => {
    if (isUpdating) {
      return <span className="status-badge updating">Updating...</span>;
    }
    
    if (!status) {
      return <span className="status-badge loading">Loading...</span>;
    }

    if (!status.isOnline) {
      return <span className="status-badge offline">Offline</span>;
    }

    const timeSinceUpdate = status.state.lastUpdateTime 
      ? Date.now() - new Date(status.state.lastUpdateTime).getTime()
      : null;

    if (!timeSinceUpdate) {
      return <span className="status-badge warning">Never Updated</span>;
    }

    const hoursOld = timeSinceUpdate / (1000 * 60 * 60);
    
    if (hoursOld > 24) {
      return <span className="status-badge warning">Outdated ({Math.round(hoursOld)}h old)</span>;
    }
    
    return <span className="status-badge up-to-date">Up to Date</span>;
  };

  return (
    <div className="signature-update-settings">
      <div className="settings-header">
        <h2>🔄 Signature Update Settings</h2>
        {getStatusBadge()}
      </div>

      {/* Current Status */}
      <div className="status-section">
        <h3>Current Status</h3>
        {status && (
          <div className="status-grid">
            <div className="status-item">
              <label>Total Signatures:</label>
              <span className="value">{status.state.signatureCount?.toLocaleString() || 500}</span>
            </div>
            <div className="status-item">
              <label>Database Version:</label>
              <span className="value">{status.state.lastUpdateVersion || status.state.currentVersion}</span>
            </div>
            <div className="status-item">
              <label>Last Update:</label>
              <span className="value">{formatDate(status.state.lastUpdateTime)}</span>
            </div>
            <div className="status-item">
              <label>Next Scheduled:</label>
              <span className="value">{formatDate(status.state.nextScheduledUpdate)}</span>
            </div>
            <div className="status-item">
              <label>Update Frequency:</label>
              <span className="value">{formatInterval(config.updateInterval)}</span>
            </div>
            <div className="status-item">
              <label>Network Status:</label>
              <span className={`value ${status.isOnline ? 'online' : 'offline'}`}>
                {status.isOnline ? '🟢 Online' : '🔴 Offline'}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Statistics */}
      {status && status.stats && (
        <div className="stats-section">
          <h3>Update Statistics</h3>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">{status.stats.totalUpdates}</div>
              <div className="stat-label">Total Updates</div>
            </div>
            <div className="stat-card success">
              <div className="stat-value">{status.stats.successfulUpdates}</div>
              <div className="stat-label">Successful</div>
            </div>
            <div className="stat-card failed">
              <div className="stat-value">{status.stats.failedUpdates}</div>
              <div className="stat-label">Failed</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">+{status.stats.signaturesAdded}</div>
              <div className="stat-label">Signatures Added</div>
            </div>
          </div>
        </div>
      )}

      {/* Configuration */}
      <div className="config-section">
        <h3>Configuration</h3>
        
        <div className="config-option">
          <label>
            <input
              type="checkbox"
              checked={config.enableAutoUpdate}
              onChange={(e) => handleConfigChange('enableAutoUpdate', e.target.checked)}
            />
            <span>Enable Automatic Updates</span>
          </label>
          <p className="help-text">Automatically check for and download signature updates</p>
        </div>

        <div className="config-option">
          <label>
            <input
              type="checkbox"
              checked={config.enableSilentUpdate}
              onChange={(e) => handleConfigChange('enableSilentUpdate', e.target.checked)}
              disabled={!config.enableAutoUpdate}
            />
            <span>Silent Updates (Background)</span>
          </label>
          <p className="help-text">Update signatures silently without notifications</p>
        </div>

        <div className="config-option">
          <label htmlFor="update-interval">Update Frequency:</label>
          <select
            id="update-interval"
            value={config.updateInterval}
            onChange={(e) => handleConfigChange('updateInterval', parseInt(e.target.value))}
            disabled={!config.enableAutoUpdate}
          >
            <option value={1800000}>30 minutes</option>
            <option value={3600000}>1 hour (Recommended)</option>
            <option value={7200000}>2 hours</option>
            <option value={14400000}>4 hours</option>
            <option value={21600000}>6 hours</option>
            <option value={43200000}>12 hours</option>
            <option value={86400000}>24 hours</option>
          </select>
          <p className="help-text">How often to check for signature updates</p>
        </div>
      </div>

      {/* Manual Update */}
      <div className="manual-update-section">
        <h3>Manual Update</h3>
        <button
          className="update-button"
          onClick={handleForceUpdate}
          disabled={isUpdating}
        >
          {isUpdating ? (
            <>
              <span className="spinner"></span>
              Updating...
            </>
          ) : (
            <>
              <span>🔄</span>
              Check for Updates Now
            </>
          )}
        </button>

        {lastUpdateResult && (
          <div className={`update-result ${lastUpdateResult.success ? 'success' : 'error'}`}>
            {lastUpdateResult.success ? (
              lastUpdateResult.upToDate ? (
                <p>✅ You're already up to date! (Version {lastUpdateResult.version})</p>
              ) : (
                <div>
                  <p>✅ Update successful!</p>
                  <ul>
                    <li>Version: {lastUpdateResult.version}</li>
                    <li>Added: {lastUpdateResult.added} signatures</li>
                    <li>Modified: {lastUpdateResult.modified} signatures</li>
                    <li>Total: {lastUpdateResult.total} signatures</li>
                  </ul>
                </div>
              )
            ) : (
              <p>❌ Update failed: {lastUpdateResult.reason || lastUpdateResult.error}</p>
            )}
          </div>
        )}
      </div>

      {/* Update History */}
      <div className="history-section">
        <h3>Recent Updates</h3>
        {updateHistory.length > 0 ? (
          <div className="history-list">
            {updateHistory.slice(0, 10).map((update, index) => (
              <div key={index} className="history-item">
                <div className="history-date">
                  {new Date(update.timestamp).toLocaleString()}
                </div>
                <div className="history-details">
                  <span className="version">v{update.version}</span>
                  <span className="changes">
                    +{update.signaturesAdded} added, {update.signaturesModified} modified
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="no-history">No update history available</p>
        )}
      </div>

      {/* Update Sources */}
      <div className="sources-section">
        <h3>Update Sources</h3>
        <p className="info-text">
          Signature updates are downloaded from multiple redundant sources:
        </p>
        <ul className="sources-list">
          <li>🌐 Primary: signatures.nebula-shield.com</li>
          <li>🔄 Backup: backup-signatures.nebula-shield.com</li>
          <li>📦 Fallback: GitHub Public Repository</li>
        </ul>
        <p className="security-note">
          ✅ All updates are verified for integrity before installation
        </p>
      </div>
    </div>
  );
};

export default SignatureUpdateSettings;
