/**
 * Startup Manager Page Component
 * 
 * Provides UI for scanning and managing Windows startup programs
 * Features:
 * - Visual startup impact analysis
 * - One-click optimization
 * - Enable/disable individual items
 * - Backup/restore functionality
 * - Real-time boot time calculations
 */

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import startupManager from '../services/startupManager';
import './StartupManager.css';

const StartupManager = () => {
  const [startupItems, setStartupItems] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [filter, setFilter] = useState('all'); // all, bloatware, optional, recommended, critical
  const [sortBy, setSortBy] = useState('impact'); // name, impact, memory
  const [selectedItems, setSelectedItems] = useState(new Set());
  const [showBackupModal, setShowBackupModal] = useState(false);
  const [, forceUpdate] = useState({});

  // Load startup items on mount
  useEffect(() => {
    scanStartup();
  }, []);

  // Scan startup programs
  const scanStartup = useCallback(async () => {
    setScanning(true);
    try {
      const result = await startupManager.scanStartupPrograms();
      if (result.success) {
        setStartupItems(result.items);
        setSummary(result.summary);
      }
    } catch (error) {
      console.error('Startup scan error:', error);
    } finally {
      setScanning(false);
      setLoading(false);
    }
  }, []);

  // Force rescan (clears cache)
  const forceRescan = useCallback(async () => {
    setScanning(true);
    try {
      const result = await startupManager.rescanStartupPrograms();
      if (result.success) {
        setStartupItems(result.items);
        setSummary(result.summary);
      }
    } catch (error) {
      console.error('Startup scan error:', error);
    } finally {
      setScanning(false);
    }
  }, []);

  // Handle filter change with forced update
  const handleFilterChange = useCallback((newFilter) => {
    console.log('Filter changed from', filter, 'to', newFilter);
    setFilter(newFilter);
    forceUpdate({}); // Force re-render
  }, [filter]);

  // Handle sort change with forced update
  const handleSortChange = useCallback((newSort) => {
    console.log('Sort changed from', sortBy, 'to', newSort);
    setSortBy(newSort);
    forceUpdate({}); // Force re-render
  }, [sortBy]);

  // Filter and sort items
  const filteredItems = useMemo(() => {
    let items = [...startupItems];

    // Apply category filter
    if (filter !== 'all') {
      items = items.filter(item => item.category === filter);
    }

    // Apply sorting
    items.sort((a, b) => {
      switch (sortBy) {
        case 'name':
          return a.name.localeCompare(b.name);
        case 'impact':
          return b.impactScore - a.impactScore;
        case 'memory':
          return b.memoryUsage - a.memoryUsage;
        default:
          return 0;
      }
    });

    return items;
  }, [startupItems, filter, sortBy]);

  // Toggle item enabled/disabled
  const toggleItem = useCallback(async (itemId, currentStatus) => {
    try {
      const result = currentStatus === 'Enabled' 
        ? await startupManager.disableStartupItem(itemId)
        : await startupManager.enableStartupItem(itemId);

      if (result.success) {
        // Update local state
        setStartupItems(prev => prev.map(item => 
          item.id === itemId 
            ? { ...item, status: currentStatus === 'Enabled' ? 'Disabled' : 'Enabled' }
            : item
        ));
        
        // Rescan to update summary stats
        const refreshedData = await startupManager.scanStartupPrograms();
        if (refreshedData.success) {
          setSummary(refreshedData.summary);
        }
      }
    } catch (error) {
      console.error('Toggle error:', error);
    }
  }, []);

  // Apply recommended optimizations
  const applyOptimizations = useCallback(async () => {
    if (!window.confirm('This will disable all bloatware and unnecessary startup programs. Continue?')) {
      return;
    }

    setScanning(true);
    try {
      const result = await startupManager.applyRecommendedOptimizations(startupItems);
      
      if (result.success) {
        alert(`✅ Optimization Complete!\n\n` +
              `Disabled: ${result.disabled.length} items\n` +
              `Boot time saved: ${result.timeSaved.toFixed(1)}s\n` +
              `Memory saved: ${result.memorySaved}MB`);
        
        // Refresh data from cache
        await scanStartup();
      }
    } catch (error) {
      console.error('Optimization error:', error);
      alert('Optimization failed: ' + error.message);
    } finally {
      setScanning(false);
    }
  }, [startupItems, scanStartup]);

  // Backup configuration
  const backupConfig = useCallback(async () => {
    try {
      const result = await startupManager.backupStartupConfig();
      if (result.success) {
        alert('✅ Backup created successfully!');
        setShowBackupModal(false);
      }
    } catch (error) {
      alert('Backup failed: ' + error.message);
    }
  }, []);

  // Restore configuration
  const restoreConfig = useCallback(async () => {
    if (!window.confirm('This will restore your previous startup configuration. Continue?')) {
      return;
    }

    try {
      const result = await startupManager.restoreStartupConfig();
      if (result.success) {
        alert('✅ Configuration restored successfully!');
        await forceRescan();
      }
    } catch (error) {
      alert('Restore failed: ' + error.message);
    }
  }, [forceRescan]);

  // Calculate optimization score
  const optimizationScore = useMemo(() => {
    return startupManager.calculateOptimizationScore(startupItems);
  }, [startupItems]);

  // Get score color
  const getScoreColor = (score) => {
    if (score >= 80) return '#10b981'; // green
    if (score >= 60) return '#f59e0b'; // yellow
    return '#ef4444'; // red
  };

  // Get impact color
  const getImpactColor = (impact) => {
    switch (impact) {
      case 'High': return '#ef4444';
      case 'Medium': return '#f59e0b';
      case 'Low': return '#10b981';
      default: return '#6b7280';
    }
  };

  // Get category badge
  const getCategoryBadge = (category) => {
    const styles = {
      bloatware: { bg: '#fee2e2', color: '#991b1b', text: '🗑️ Bloatware' },
      optional: { bg: '#fef3c7', color: '#92400e', text: '⚙️ Optional' },
      recommended: { bg: '#dbeafe', color: '#1e40af', text: '👍 Recommended' },
      critical: { bg: '#dcfce7', color: '#166534', text: '🛡️ Critical' }
    };
    
    const style = styles[category] || styles.optional;
    
    return (
      <span style={{
        background: style.bg,
        color: style.color,
        padding: '2px 8px',
        borderRadius: '4px',
        fontSize: '11px',
        fontWeight: '600'
      }}>
        {style.text}
      </span>
    );
  };

  if (loading) {
    return (
      <div className="startup-manager loading">
        <div className="loading-spinner"></div>
        <p>Scanning startup programs...</p>
      </div>
    );
  }

  return (
    <div className="startup-manager">
      {/* Header */}
      <div className="startup-header">
        <div className="header-content">
          <h1>🚀 Startup Manager</h1>
          <p>
            Optimize your boot time by managing startup programs
            {filter !== 'all' && (
              <span style={{ 
                marginLeft: '10px', 
                padding: '2px 8px', 
                background: '#eff6ff', 
                color: '#1e40af',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: '600'
              }}>
                Showing: {filter.charAt(0).toUpperCase() + filter.slice(1)} ({filteredItems.length})
              </span>
            )}
          </p>
        </div>
        
        <div className="header-actions">
          <button 
            className="btn-scan"
            onClick={forceRescan}
            disabled={scanning}
          >
            {scanning ? '🔄 Scanning...' : '🔍 Rescan'}
          </button>
          
          <button 
            className="btn-optimize"
            onClick={applyOptimizations}
            disabled={scanning || !summary}
          >
            ⚡ Auto-Optimize
          </button>
          
          <button 
            className="btn-backup"
            onClick={() => setShowBackupModal(true)}
          >
            💾 Backup
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="summary-cards">
          {/* Optimization Score */}
          <div className="summary-card score-card">
            <div className="card-icon">📊</div>
            <div className="card-content">
              <h3>Optimization Score</h3>
              <div 
                className="score-value"
                style={{ color: getScoreColor(optimizationScore) }}
              >
                {optimizationScore}/100
              </div>
              <div className="score-bar">
                <div 
                  className="score-fill"
                  style={{ 
                    width: `${optimizationScore}%`,
                    background: getScoreColor(optimizationScore)
                  }}
                />
              </div>
            </div>
          </div>

          {/* Boot Time */}
          <div className="summary-card">
            <div className="card-icon">⏱️</div>
            <div className="card-content">
              <h3>Boot Time</h3>
              <div className="stat-value">{summary.impact.currentBootTime}s</div>
              {parseFloat(summary.impact.potentialTimeSaved) > 0 && (
                <div className="stat-improvement">
                  Can save {summary.impact.potentialTimeSaved}s
                  <span className="improvement-badge">
                    -{summary.impact.improvementPercentage}%
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Memory Usage */}
          <div className="summary-card">
            <div className="card-icon">💾</div>
            <div className="card-content">
              <h3>Memory Usage</h3>
              <div className="stat-value">{summary.impact.currentMemoryUsage}MB</div>
              {summary.impact.potentialMemorySaved > 0 && (
                <div className="stat-improvement">
                  Can save {summary.impact.potentialMemorySaved}MB
                </div>
              )}
            </div>
          </div>

          {/* Startup Items */}
          <div className="summary-card">
            <div className="card-icon">📋</div>
            <div className="card-content">
              <h3>Startup Items</h3>
              <div className="stat-value">{summary.enabled}/{summary.total}</div>
              <div className="stat-breakdown">
                <span className="bloat-count">
                  🗑️ {summary.categories.bloatware} bloatware
                </span>
                <span className="optional-count">
                  ⚙️ {summary.categories.optional} optional
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters and Sort */}
      <div className="controls-bar" key={`controls-${filter}-${sortBy}`}>
        <div className="filters">
          <label>
            Filter: 
            <span style={{
              marginLeft: '8px',
              fontSize: '12px',
              color: '#6b7280',
              fontWeight: 'normal'
            }}>
              ({filteredItems.length} items)
            </span>
          </label>
          <button 
            type="button"
            className={filter === 'all' ? 'active' : ''}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              handleFilterChange('all');
            }}
          >
            All ({startupItems.length})
          </button>
          <button 
            type="button"
            className={filter === 'bloatware' ? 'active' : ''}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              handleFilterChange('bloatware');
            }}
          >
            🗑️ Bloatware ({startupItems.filter(i => i.category === 'bloatware').length})
          </button>
          <button 
            type="button"
            className={filter === 'optional' ? 'active' : ''}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              handleFilterChange('optional');
            }}
          >
            ⚙️ Optional ({startupItems.filter(i => i.category === 'optional').length})
          </button>
          <button 
            type="button"
            className={filter === 'recommended' ? 'active' : ''}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              handleFilterChange('recommended');
            }}
          >
            👍 Recommended ({startupItems.filter(i => i.category === 'recommended').length})
          </button>
          <button 
            type="button"
            className={filter === 'critical' ? 'active' : ''}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              handleFilterChange('critical');
            }}
          >
            🛡️ Critical ({startupItems.filter(i => i.category === 'critical').length})
          </button>
        </div>

        <div className="sort-controls">
          <label>Sort by:</label>
          <select 
            value={sortBy} 
            onChange={(e) => {
              e.preventDefault();
              handleSortChange(e.target.value);
            }}
          >
            <option value="impact">Impact (High to Low)</option>
            <option value="name">Name (A-Z)</option>
            <option value="memory">Memory Usage</option>
          </select>
        </div>
      </div>

      {/* Startup Items List */}
      <div className="startup-items-container" key={`items-${filter}-${filteredItems.length}`}>
        {filteredItems.length === 0 ? (
          <div className="empty-state">
            <p>No startup items found in this category</p>
            <button 
              type="button"
              onClick={() => handleFilterChange('all')}
              style={{
                marginTop: '12px',
                padding: '8px 16px',
                background: '#3b82f6',
                color: 'white',
                border: 'none',
                borderRadius: '8px',
                cursor: 'pointer',
                fontWeight: '600'
              }}
            >
              Show All Items
            </button>
          </div>
        ) : (
          <div className="startup-items-list">
            {filteredItems.map(item => (
              <div 
                key={`${item.id}-${filter}`} 
                className={`startup-item ${item.status.toLowerCase()}`}
              >
                <div className="item-header">
                  <div className="item-info">
                    <div className="item-name-row">
                      <h4>{item.name}</h4>
                      {getCategoryBadge(item.category)}
                    </div>
                    <p className="item-publisher">{item.publisher}</p>
                  </div>

                  <div className="item-toggle">
                    <label className="toggle-switch">
                      <input
                        type="checkbox"
                        checked={item.status === 'Enabled'}
                        onChange={() => toggleItem(item.id, item.status)}
                      />
                      <span className="toggle-slider"></span>
                    </label>
                    <span className={`status-label ${item.status.toLowerCase()}`}>
                      {item.status}
                    </span>
                  </div>
                </div>

                <div className="item-stats">
                  <div className="stat">
                    <span 
                      className="impact-badge"
                      style={{ background: getImpactColor(item.startupImpact) }}
                    >
                      {item.startupImpact} Impact
                    </span>
                  </div>
                  <div className="stat">
                    <span className="stat-label">⏱️</span>
                    {item.bootDelay}s delay
                  </div>
                  <div className="stat">
                    <span className="stat-label">💾</span>
                    {item.memoryUsage}MB
                  </div>
                  <div className="stat">
                    <span className="stat-label">🖥️</span>
                    {item.cpuUsage}% CPU
                  </div>
                  <div className="stat">
                    <span className="stat-label">📊</span>
                    Score: {item.impactScore.toFixed(1)}
                  </div>
                </div>

                <div className="item-recommendation">
                  <strong>💡 Recommendation:</strong> {item.recommendation}
                  <br />
                  <span className="recommendation-reason">{item.reason}</span>
                </div>

                <div className="item-details">
                  <div className="detail-row">
                    <span className="detail-label">Location:</span>
                    <code>{item.location}</code>
                  </div>
                  <div className="detail-row">
                    <span className="detail-label">Command:</span>
                    <code className="command-path">{item.command}</code>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Backup Modal */}
      {showBackupModal && (
        <div className="modal-overlay" onClick={() => setShowBackupModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>💾 Backup & Restore</h2>
            
            <div className="modal-section">
              <h3>Create Backup</h3>
              <p>Save your current startup configuration before making changes</p>
              <button className="btn-primary" onClick={backupConfig}>
                💾 Create Backup Now
              </button>
            </div>

            <div className="modal-divider"></div>

            <div className="modal-section">
              <h3>Restore Backup</h3>
              <p>Restore your previous startup configuration</p>
              <button className="btn-secondary" onClick={restoreConfig}>
                ↩️ Restore from Backup
              </button>
            </div>

            <button 
              className="modal-close"
              onClick={() => setShowBackupModal(false)}
            >
              ✕
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

// Memoize entire component to prevent unnecessary re-renders
export default React.memo(StartupManager);
