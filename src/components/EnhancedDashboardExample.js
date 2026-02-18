/**
 * Enhanced Dashboard Example
 * Demonstrates all features of the new API client
 */

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Activity,
  HardDrive,
  AlertTriangle,
  Wifi,
  WifiOff,
  RefreshCw,
  Database,
  Trash2,
  Download
} from 'lucide-react';
import { useAPI, useBatchAPI, useMutation, useCache, useOffline } from '../hooks/useAPI';
import apiClient from '../services/apiClient';
import toast from 'react-hot-toast';
import './EnhancedDashboardExample.css';

const EnhancedDashboardExample = () => {
  const [selectedTab, setSelectedTab] = useState('overview');
  const offline = useOffline();

  return (
    <div className="enhanced-dashboard">
      {/* Offline Indicator */}
      {offline && (
        <motion.div
          className="offline-banner"
          initial={{ y: -50, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
        >
          <WifiOff size={20} />
          <span>You're offline - showing cached data</span>
        </motion.div>
      )}

      {/* Header */}
      <div className="dashboard-header">
        <h1>Enhanced Dashboard</h1>
        <p>Demonstrating API Client Features</p>
      </div>

      {/* Tabs */}
      <div className="dashboard-tabs">
        <button
          className={selectedTab === 'overview' ? 'active' : ''}
          onClick={() => setSelectedTab('overview')}
        >
          <Activity size={18} />
          Overview
        </button>
        <button
          className={selectedTab === 'batch' ? 'active' : ''}
          onClick={() => setSelectedTab('batch')}
        >
          <Database size={18} />
          Batch Requests
        </button>
        <button
          className={selectedTab === 'mutations' ? 'active' : ''}
          onClick={() => setSelectedTab('mutations')}
        >
          <RefreshCw size={18} />
          Mutations
        </button>
        <button
          className={selectedTab === 'cache' ? 'active' : ''}
          onClick={() => setSelectedTab('cache')}
        >
          <HardDrive size={18} />
          Cache Manager
        </button>
      </div>

      {/* Content */}
      <div className="dashboard-content">
        {selectedTab === 'overview' && <OverviewTab />}
        {selectedTab === 'batch' && <BatchTab />}
        {selectedTab === 'mutations' && <MutationsTab />}
        {selectedTab === 'cache' && <CacheTab />}
      </div>
    </div>
  );
};

/**
 * Overview Tab - Single API Request with Background Refresh
 */
const OverviewTab = () => {
  const { data, loading, error, fromCache, refresh } = useAPI('/status', {
    cache: true,
    cacheTTL: 5 * 60 * 1000, // 5 minutes
    backgroundRefresh: true,
    refreshInterval: 30000, // 30 seconds
    onSuccess: (data) => {
      console.log('Status loaded:', data);
    }
  });

  const handleRefresh = async () => {
    toast.loading('Refreshing...');
    try {
      await refresh();
      toast.dismiss();
      toast.success('Refreshed!');
    } catch (err) {
      toast.dismiss();
      toast.error('Failed to refresh');
    }
  };

  if (loading && !data) {
    return <LoadingSpinner />;
  }

  if (error && !data) {
    return (
      <ErrorDisplay
        error={error}
        onRetry={refresh}
      />
    );
  }

  return (
    <div className="overview-content">
      {/* Status Indicator */}
      <div className="status-indicator">
        {fromCache && (
          <div className="cache-badge">
            <Database size={16} />
            Cached Data
          </div>
        )}
        <button onClick={handleRefresh} className="refresh-btn">
          <RefreshCw size={18} />
          Refresh
        </button>
      </div>

      {/* System Status */}
      <div className="status-cards">
        <StatusCard
          icon={<Shield size={24} />}
          title="Protection"
          value={data?.protection_enabled ? 'Active' : 'Disabled'}
          status={data?.protection_enabled ? 'success' : 'warning'}
        />
        <StatusCard
          icon={<Activity size={24} />}
          title="Real-Time"
          value={data?.real_time_protection ? 'On' : 'Off'}
          status={data?.real_time_protection ? 'success' : 'warning'}
        />
        <StatusCard
          icon={<AlertTriangle size={24} />}
          title="Threats"
          value={data?.total_threats_found || 0}
          status={data?.total_threats_found > 0 ? 'danger' : 'success'}
        />
      </div>

      {/* Additional Info */}
      <div className="info-panel">
        <h3>System Information</h3>
        <pre>{JSON.stringify(data, null, 2)}</pre>
      </div>
    </div>
  );
};

/**
 * Batch Tab - Multiple API Requests
 */
const BatchTab = () => {
  const { data, loading, errors, refresh } = useBatchAPI([
    { endpoint: '/status', options: { cache: true } },
    { endpoint: '/stats', options: { cache: true } },
    { endpoint: '/quarantine', options: { cache: true } },
    { endpoint: '/scan/results', options: { cache: true } }
  ], {
    parallel: true,
    maxConcurrent: 4,
    continueOnError: true,
    onSuccess: (result) => {
      console.log('Batch complete:', result);
    }
  });

  if (loading) {
    return <LoadingSpinner text="Loading multiple endpoints..." />;
  }

  const [status, stats, quarantine, scanResults] = data || [];

  return (
    <div className="batch-content">
      <div className="batch-header">
        <h2>Batch API Requests</h2>
        <button onClick={refresh} className="refresh-btn">
          <RefreshCw size={18} />
          Refresh All
        </button>
      </div>

      {errors.length > 0 && (
        <div className="error-summary">
          <AlertTriangle size={20} />
          <span>{errors.length} request(s) failed</span>
        </div>
      )}

      <div className="batch-grid">
        <DataCard title="System Status" data={status} />
        <DataCard title="Statistics" data={stats} />
        <DataCard title="Quarantine" data={quarantine} />
        <DataCard title="Scan Results" data={scanResults} />
      </div>
    </div>
  );
};

/**
 * Mutations Tab - POST/PUT/DELETE Operations
 */
const MutationsTab = () => {
  const quickScan = useMutation('/scan/quick', {
    method: 'POST',
    onSuccess: (data) => {
      toast.success(`Scan completed! Found ${data.threatsFound || 0} threats`);
    },
    onError: (error) => {
      toast.error('Scan failed: ' + error.message);
    }
  });

  const updateSignatures = useMutation('/signatures/update', {
    method: 'POST',
    onSuccess: () => {
      toast.success('Signatures updated successfully!');
    },
    onError: (error) => {
      toast.error('Update failed: ' + error.message);
    }
  });

  const handleQuickScan = async () => {
    try {
      await quickScan.mutate({});
    } catch (err) {
      // Error already handled by onError callback
    }
  };

  const handleUpdateSignatures = async () => {
    try {
      await updateSignatures.mutate({});
    } catch (err) {
      // Error already handled by onError callback
    }
  };

  return (
    <div className="mutations-content">
      <h2>Mutation Operations</h2>
      <p>POST, PUT, DELETE requests with automatic retry</p>

      <div className="mutation-actions">
        <ActionCard
          icon={<Shield size={32} />}
          title="Quick Scan"
          description="Start a quick system scan"
          loading={quickScan.loading}
          error={quickScan.error}
          onAction={handleQuickScan}
          result={quickScan.data}
        />

        <ActionCard
          icon={<Download size={32} />}
          title="Update Signatures"
          description="Download latest threat signatures"
          loading={updateSignatures.loading}
          error={updateSignatures.error}
          onAction={handleUpdateSignatures}
          result={updateSignatures.data}
        />
      </div>
    </div>
  );
};

/**
 * Cache Tab - Cache Management
 */
const CacheTab = () => {
  const { stats, clear, refresh } = useCache();
  const [prefetching, setPrefetching] = useState(false);

  const handleClear = async () => {
    if (window.confirm('Clear all cached data?')) {
      await clear();
      toast.success('Cache cleared!');
    }
  };

  const handlePrefetch = async () => {
    setPrefetching(true);
    toast.loading('Prefetching data...');
    
    try {
      await apiClient.prefetch([
        '/status',
        '/stats',
        '/quarantine',
        '/scan/results'
      ]);
      
      toast.dismiss();
      toast.success('Data prefetched successfully!');
      await refresh();
    } catch (error) {
      toast.dismiss();
      toast.error('Prefetch failed: ' + error.message);
    } finally {
      setPrefetching(false);
    }
  };

  return (
    <div className="cache-content">
      <h2>Cache Management</h2>
      <p>View and manage cached API responses</p>

      {/* Cache Stats */}
      <div className="cache-stats">
        <StatItem
          label="Total Entries"
          value={stats?.totalEntries || 0}
          icon={<Database size={20} />}
        />
        <StatItem
          label="Pending Requests"
          value={stats?.pendingRequests || 0}
          icon={<RefreshCw size={20} />}
        />
        <StatItem
          label="Background Tasks"
          value={stats?.activeBackgroundTasks || 0}
          icon={<Activity size={20} />}
        />
        <StatItem
          label="Queued Requests"
          value={stats?.queuedRequests || 0}
          icon={<HardDrive size={20} />}
        />
      </div>

      {/* Cache Actions */}
      <div className="cache-actions">
        <button onClick={handleClear} className="danger-btn">
          <Trash2 size={18} />
          Clear Cache
        </button>
        <button onClick={refresh} className="primary-btn">
          <RefreshCw size={18} />
          Refresh Stats
        </button>
        <button
          onClick={handlePrefetch}
          className="primary-btn"
          disabled={prefetching}
        >
          <Download size={18} />
          {prefetching ? 'Prefetching...' : 'Prefetch Data'}
        </button>
      </div>

      {/* Cache Details */}
      <div className="cache-details">
        <h3>Cache Configuration</h3>
        <div className="config-item">
          <span>Offline Mode:</span>
          <span>{stats?.offlineMode ? 'Yes' : 'No'}</span>
        </div>
        <div className="config-item">
          <span>Background Refresh:</span>
          <span>{stats?.backgroundRefreshEnabled ? 'Enabled' : 'Disabled'}</span>
        </div>
      </div>
    </div>
  );
};

// Helper Components

const LoadingSpinner = ({ text = 'Loading...' }) => (
  <div className="loading-spinner">
    <RefreshCw size={32} className="spinning" />
    <p>{text}</p>
  </div>
);

const ErrorDisplay = ({ error, onRetry }) => (
  <div className="error-display">
    <AlertTriangle size={48} />
    <h3>Error Loading Data</h3>
    <p>{error.message}</p>
    <button onClick={onRetry} className="retry-btn">
      <RefreshCw size={18} />
      Retry
    </button>
  </div>
);

const StatusCard = ({ icon, title, value, status }) => (
  <div className={`status-card status-${status}`}>
    <div className="card-icon">{icon}</div>
    <div className="card-content">
      <div className="card-title">{title}</div>
      <div className="card-value">{value}</div>
    </div>
  </div>
);

const DataCard = ({ title, data }) => (
  <div className="data-card">
    <h3>{title}</h3>
    {data ? (
      <pre>{JSON.stringify(data, null, 2)}</pre>
    ) : (
      <p>No data available</p>
    )}
  </div>
);

const ActionCard = ({ icon, title, description, loading, error, onAction, result }) => (
  <div className="action-card">
    <div className="action-icon">{icon}</div>
    <h3>{title}</h3>
    <p>{description}</p>
    
    {error && (
      <div className="action-error">
        <AlertTriangle size={16} />
        <span>{error.message}</span>
      </div>
    )}
    
    {result && (
      <div className="action-result">
        <pre>{JSON.stringify(result, null, 2)}</pre>
      </div>
    )}
    
    <button
      onClick={onAction}
      disabled={loading}
      className="action-btn"
    >
      {loading ? 'Processing...' : 'Execute'}
    </button>
  </div>
);

const StatItem = ({ label, value, icon }) => (
  <div className="stat-item">
    <div className="stat-icon">{icon}</div>
    <div className="stat-content">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  </div>
);

export default EnhancedDashboardExample;
