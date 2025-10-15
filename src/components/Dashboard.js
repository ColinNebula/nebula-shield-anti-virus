import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  Zap,
  TrendingUp,
  FileText,
  Eye,
  Download,
  FileDown,
  RefreshCw
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area, PieChart, Pie, Cell } from 'recharts';
import AntivirusAPI from '../services/antivirusApi';
import pdfReportService from '../services/pdfReportService';
import realtimeMonitor from '../services/realtimeMonitor';
import NebulaLogo from './NebulaLogo';
import ProtectionMonitor from './ProtectionMonitor';
import toast from 'react-hot-toast';
import './Dashboard.css';

const Dashboard = () => {
  const [systemStatus, setSystemStatus] = useState(null);
  const [scanResults, setScanResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [threatData, setThreatData] = useState([]);
  const [activityData, setActivityData] = useState([]);
  const [lastUpdate, setLastUpdate] = useState(new Date());
  const [isScanning, setIsScanning] = useState(false);
  const [currentTime, setCurrentTime] = useState(new Date());
  
  // Real-time monitoring state
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const [updateCount, setUpdateCount] = useState(0);
  const [showLiveIndicator, setShowLiveIndicator] = useState(false);

  useEffect(() => {
    // Start real-time monitoring
    realtimeMonitor.start();
    
    // Subscribe to real-time events
    const unsubscribe = realtimeMonitor.subscribe((event, data) => {
      handleRealtimeEvent(event, data);
    });
    
    // Update current time every minute to refresh "time ago" displays
    const timeInterval = setInterval(() => {
      setCurrentTime(new Date());
    }, 60000); // Update every minute
    
    return () => {
      unsubscribe();
      realtimeMonitor.stop();
      clearInterval(timeInterval);
    };
  }, []);

  const handleRealtimeEvent = (event, data) => {
    switch (event) {
      case 'initial_data':
        setSystemStatus(data.systemStatus);
        setScanResults(data.scanResults);
        setLastUpdate(new Date());
        if (data.stats?.scanHistory) {
          generateChartDataFromHistory(data.stats.scanHistory);
        } else {
          generateChartData();
        }
        setLoading(false);
        break;
        
      case 'connection_status':
        setConnectionStatus(data.status);
        if (data.lastUpdate) setLastUpdate(new Date(data.lastUpdate));
        if (data.updateCount) setUpdateCount(data.updateCount);
        break;
        
      case 'new_log':
        // Show live indicator with pulse
        setShowLiveIndicator(true);
        setTimeout(() => setShowLiveIndicator(false), 2000);
        
        // Show toast for critical threats
        if (data.severity === 'critical' || data.severity === 'high') {
          toast.error(`🚨 ${data.severity.toUpperCase()}: ${data.threatType}`, {
            duration: 5000,
            icon: '⚠️'
          });
        }
        break;
        
      case 'critical_alert':
        toast.error(`🔥 CRITICAL ALERT: ${data.message || 'Security threat detected'}`, {
          duration: 8000,
          icon: '🚨'
        });
        setShowLiveIndicator(true);
        setTimeout(() => setShowLiveIndicator(false), 3000);
        break;
        
      case 'metadata_update':
        setLastUpdate(new Date(data.lastUpdate));
        setUpdateCount(data.updateCount);
        break;
        
      case 'batch_update':
        // Multiple events processed
        setShowLiveIndicator(true);
        setTimeout(() => setShowLiveIndicator(false), 1500);
        break;
        
      case 'fallback_update':
        if (data.systemStatus) setSystemStatus(data.systemStatus);
        setLastUpdate(new Date());
        break;
        
      default:
        break;
    }
  };

  const loadDashboardData = async () => {
    setLoading(true);
    const status = await realtimeMonitor.refresh();
    toast.success('Dashboard refreshed');
  };

  const generateChartData = () => {
    // Generate activity data for the last 7 days
    const activity = [];
    const threats = [];
    const now = new Date();
    
    for (let i = 6; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      
      activity.push({
        date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        scans: Math.floor(Math.random() * 100) + 20,
        threats: Math.floor(Math.random() * 5),
      });
    }

    const threatTypes = [
      { name: 'Clean', value: 85, color: '#10b981' },
      { name: 'Virus', value: 8, color: '#ef4444' },
      { name: 'Malware', value: 4, color: '#f59e0b' },
      { name: 'Suspicious', value: 3, color: '#8b5cf6' },
    ];

    setActivityData(activity);
    setThreatData(threatTypes);
  };

  const generateChartDataFromHistory = (scanHistory) => {
    // Generate activity data from real scan history
    const activity = [];
    const now = new Date();
    
    for (let i = 6; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const dayStart = new Date(date);
      dayStart.setHours(0, 0, 0, 0);
      const dayEnd = new Date(date);
      dayEnd.setHours(23, 59, 59, 999);
      
      const dayScans = scanHistory.filter(scan => {
        const scanDate = new Date(scan.scanTime);
        return scanDate >= dayStart && scanDate <= dayEnd;
      });
      
      activity.push({
        date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        scans: dayScans.length,
        threats: dayScans.filter(scan => scan.status === 'infected').length,
      });
    }

    // Calculate threat distribution from history
    const cleanCount = scanHistory.filter(scan => scan.status === 'clean').length;
    const infectedCount = scanHistory.filter(scan => scan.status === 'infected').length;
    const total = scanHistory.length || 1;
    
    const threatTypes = [
      { name: 'Clean', value: Math.round((cleanCount / total) * 100), color: '#10b981' },
      { name: 'Threats', value: Math.round((infectedCount / total) * 100), color: '#ef4444' },
    ];

    setActivityData(activity);
    setThreatData(threatTypes);
  };

  const handleQuickScan = async () => {
    if (isScanning) return;
    
    setIsScanning(true);
    const loadingToast = toast.loading('🔍 Quick scan in progress...');
    
    try {
      const result = await AntivirusAPI.startQuickScan();
      
      toast.dismiss(loadingToast);
      
      if (result.threatsFound > 0) {
        toast.error(`⚠️ Quick scan complete: ${result.threatsFound} threat${result.threatsFound > 1 ? 's' : ''} found!`, {
          duration: 5000,
        });
      } else {
        toast.success(`✅ Quick scan complete: No threats detected (${result.filesScanned} files scanned)`, {
          duration: 4000,
        });
      }
      
      // Refresh dashboard data to show updated stats
      await loadDashboardData();
      
    } catch (error) {
      toast.dismiss(loadingToast);
      toast.error('❌ Quick scan failed: ' + error.message);
      console.error('Quick scan error:', error);
    } finally {
      setIsScanning(false);
    }
  };

  const handleToggleProtection = async () => {
    const loadingToast = toast.loading('⚙️ Toggling protection...');
    
    try {
      const result = await AntivirusAPI.toggleRealTimeProtection();
      
      toast.dismiss(loadingToast);
      
      if (result.enabled) {
        toast.success('🛡️ Real-time protection enabled!', {
          duration: 3000,
        });
      } else {
        toast.success('🔓 Real-time protection disabled', {
          icon: '⚠️',
          duration: 3000,
        });
      }
      
      // Refresh dashboard data to show updated protection status
      await loadDashboardData();
      
    } catch (error) {
      toast.dismiss(loadingToast);
      toast.error('❌ Failed to toggle protection: ' + error.message);
      console.error('Toggle protection error:', error);
    }
  };

  const handleUpdateSignatures = async () => {
    const loadingToast = toast.loading('📥 Updating virus signatures...');
    
    try {
      await AntivirusAPI.updateSignatures();
      
      toast.dismiss(loadingToast);
      toast.success('✅ Virus signatures updated successfully!');
      
      // Refresh system status to show updated info
      await loadDashboardData();
    } catch (error) {
      toast.dismiss(loadingToast);
      toast.error('❌ Failed to update signatures: ' + error.message);
      console.error('Signature update error:', error);
    }
  };

  const handleExportHealthReport = async () => {
    const loadingToast = toast.loading('📄 Generating health report...');

    try {
      const healthData = {
        healthScore: systemStatus?.real_time_protection ? 95 : 65,
        realtimeProtection: systemStatus?.real_time_protection || false,
        firewallStatus: 'Active',
        lastScan: lastUpdate,
        signatures: systemStatus?.signature_count || 0,
        lastUpdate: lastUpdate,
        scansPerformed: activityData.reduce((sum, day) => sum + day.scans, 0),
        threatsBlocked: activityData.reduce((sum, day) => sum + day.threats, 0),
        filesQuarantined: scanResults.filter(r => r.threat_type !== 'CLEAN').length,
        updatesApplied: 3,
        systemResources: {
          cpu: Math.floor(Math.random() * 30) + 10,
          memory: Math.floor(Math.random() * 40) + 20,
          disk: Math.floor(Math.random() * 20) + 30
        }
      };

      await pdfReportService.downloadHealthReport(
        healthData,
        `system-health-${new Date().toISOString().split('T')[0]}.pdf`
      );

      toast.dismiss(loadingToast);
      toast.success('✅ Health report downloaded!');
    } catch (error) {
      toast.dismiss(loadingToast);
      toast.error('Failed to generate report: ' + error.message);
      console.error('PDF generation error:', error);
    }
  };

  const handleExportThreatReport = async () => {
    const loadingToast = toast.loading('📄 Generating threat analysis...');

    try {
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - 7);

      const threatData = {
        startDate: startDate.toLocaleDateString(),
        endDate: endDate.toLocaleDateString(),
        totalThreats: scanResults.filter(r => r.threat_type !== 'CLEAN').length,
        quarantined: scanResults.filter(r => r.threat_type !== 'CLEAN').length,
        removed: 0,
        critical: scanResults.filter(r => r.threat_type === 'VIRUS').length,
        threatTypes: [
          { type: 'Virus', count: scanResults.filter(r => r.threat_type === 'VIRUS').length },
          { type: 'Malware', count: scanResults.filter(r => r.threat_type === 'MALWARE').length },
          { type: 'Suspicious', count: scanResults.filter(r => r.threat_type === 'SUSPICIOUS').length }
        ].filter(t => t.count > 0),
        topThreats: scanResults
          .filter(r => r.threat_type !== 'CLEAN')
          .slice(0, 10)
          .map(r => ({
            name: r.threat_name || 'Unknown Threat',
            type: r.threat_type,
            severity: r.threat_type === 'VIRUS' ? 'High' : 'Medium',
            firstSeen: r.scan_time || Date.now()
          }))
      };

      await pdfReportService.downloadThreatReport(
        threatData,
        `threat-analysis-${new Date().toISOString().split('T')[0]}.pdf`
      );

      toast.dismiss(loadingToast);
      toast.success('✅ Threat report downloaded!');
    } catch (error) {
      toast.dismiss(loadingToast);
      toast.error('Failed to generate report: ' + error.message);
      console.error('PDF generation error:', error);
    }
  };

  const stats = [
    {
      title: 'Total Scanned',
      value: systemStatus?.total_scanned_files || 0,
      change: '+12%',
      trend: 'up',
      icon: FileText,
      color: 'blue'
    },
    {
      title: 'Threats Found',
      value: systemStatus?.total_threats_found || 0,
      change: '-8%',
      trend: 'down',
      icon: AlertTriangle,
      color: 'red'
    },
    {
      title: 'Protection Status',
      value: systemStatus?.real_time_protection ? 'Active' : 'Inactive',
      change: systemStatus?.real_time_protection ? '✓ Monitoring' : '⚠ Disabled',
      trend: systemStatus?.real_time_protection ? 'up' : 'down',
      icon: Shield,
      color: systemStatus?.real_time_protection ? 'green' : 'red'
    },
    {
      title: 'Last Update',
      value: (() => {
        const seconds = Math.floor((new Date() - lastUpdate) / 1000);
        if (seconds < 60) return 'Just now';
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes} min${minutes > 1 ? 's' : ''} ago`;
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
        const days = Math.floor(hours / 24);
        return `${days} day${days > 1 ? 's' : ''} ago`;
      })(),
      change: 'Up to date',
      trend: 'up',
      icon: Download,
      color: 'purple'
    }
  ];

  const recentThreats = scanResults
    .filter(result => result.threat_type !== 'CLEAN')
    .slice(0, 5);

  if (loading) {
    return (
      <div className="dashboard-loading">
        <div className="loading-content">
          <div className="spinner"></div>
          <p>Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <motion.div
      className="dashboard"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      {/* Page Header */}
      <div className="page-header">
        <div className="header-content">
          <div className="header-left">
            <NebulaLogo size={40} animated={true} glow={true} />
            <div className="header-text">
              <motion.h1
                className="page-title"
                initial={{ y: -20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.1 }}
              >
                Dashboard
              </motion.h1>
              <motion.p
                className="page-subtitle"
                initial={{ y: -20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.2 }}
              >
                {/* Connection Status Badge */}
                <span className={`connection-badge connection-${connectionStatus}`}>
                  {connectionStatus === 'connected' && '🟢 Live'}
                  {connectionStatus === 'connecting' && '� Connecting'}
                  {connectionStatus === 'reconnecting' && '� Reconnecting'}
                  {connectionStatus === 'disconnected' && '🔴 Offline'}
                </span>
                
                {/* Live Update Indicator */}
                {showLiveIndicator && (
                  <motion.span
                    className="live-pulse"
                    initial={{ scale: 0.8, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0.8, opacity: 0 }}
                  >
                    ⚡ Live Update
                  </motion.span>
                )}
                
                {' • '}
                Last updated: {lastUpdate.toLocaleTimeString()}
                
                {updateCount > 0 && ` • ${updateCount} updates`}
                
                {systemStatus?.real_time_protection && ' • 🛡️ Protected'}
              </motion.p>
            </div>
          </div>
          <div className="header-right">
            <motion.button
              className="btn btn-secondary"
              onClick={() => {
                loadDashboardData();
              }}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              title="Refresh dashboard data"
            >
              <RefreshCw size={16} />
              Refresh
            </motion.button>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <motion.div
        className="stats-grid"
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.3 }}
      >
        {stats.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <motion.div
              key={stat.title}
              className={`stat-card ${stat.color}`}
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: 0.4 + index * 0.1 }}
              whileHover={{ y: -4, transition: { duration: 0.2 } }}
            >
              <div className="stat-header">
                <div className={`stat-icon ${stat.color}`}>
                  <Icon size={24} />
                </div>
                <div className={`stat-change ${stat.trend}`}>
                  <TrendingUp size={16} />
                  <span>{stat.change}</span>
                </div>
              </div>
              <div className="stat-content">
                <h3 className="stat-value">{stat.value.toLocaleString()}</h3>
                <p className="stat-label">{stat.title}</p>
              </div>
            </motion.div>
          );
        })}
      </motion.div>

      {/* Real-time Protection Monitor */}
      <ProtectionMonitor isActive={systemStatus?.real_time_protection || false} />

      {/* Charts Section */}
      <div className="charts-section">
        <div className="charts-grid">
          {/* Activity Chart */}
          <motion.div
            className="chart-card"
            initial={{ x: -20, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            <div className="chart-header">
              <div className="chart-title">
                <Activity size={20} />
                <h3>Scan Activity</h3>
              </div>
              <div className="chart-legend">
                <div className="legend-item">
                  <div className="legend-color" style={{ background: '#4f46e5' }}></div>
                  <span>Scans</span>
                </div>
                <div className="legend-item">
                  <div className="legend-color" style={{ background: '#ef4444' }}></div>
                  <span>Threats</span>
                </div>
              </div>
            </div>
            <div className="chart-content">
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={activityData}>
                  <defs>
                    <linearGradient id="scansGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#4f46e5" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#4f46e5" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="threatsGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="date" stroke="#a1a1aa" />
                  <YAxis stroke="#a1a1aa" />
                  <Tooltip
                    contentStyle={{
                      background: '#1e2139',
                      border: '1px solid #374151',
                      borderRadius: '8px',
                      color: '#ffffff'
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="scans"
                    stroke="#4f46e5"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#scansGradient)"
                  />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    stroke="#ef4444"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#threatsGradient)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </motion.div>

          {/* Threat Distribution */}
          <motion.div
            className="chart-card"
            initial={{ x: 20, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ delay: 0.6 }}
          >
            <div className="chart-header">
              <div className="chart-title">
                <Eye size={20} />
                <h3>Threat Distribution</h3>
              </div>
            </div>
            <div className="chart-content">
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={threatData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={120}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {threatData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: '#1e2139',
                      border: '1px solid #374151',
                      borderRadius: '8px',
                      color: '#ffffff'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="pie-legend">
                {threatData.map((entry, index) => (
                  <div key={index} className="pie-legend-item">
                    <div
                      className="pie-legend-color"
                      style={{ background: entry.color }}
                    ></div>
                    <span>{entry.name}</span>
                    <span className="pie-legend-value">{entry.value}%</span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        </div>
      </div>

      {/* Recent Activity */}
      <motion.div
        className="recent-activity"
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.7 }}
      >
        <div className="activity-header">
          <h3>Recent Threats</h3>
          <span className="activity-count">{recentThreats.length} items</span>
        </div>
        <div className="activity-list">
          {recentThreats.length > 0 ? (
            recentThreats.map((threat, index) => (
              <motion.div
                key={index}
                className="activity-item"
                initial={{ x: -20, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                transition={{ delay: 0.8 + index * 0.1 }}
              >
                <div className="activity-icon danger">
                  <AlertTriangle size={16} />
                </div>
                <div className="activity-content">
                  <h4>{threat.threat_name || 'Unknown Threat'}</h4>
                  <p>{threat.file_path}</p>
                </div>
                <div className="activity-meta">
                  <span className="activity-time">
                    <Clock size={14} />
                    {new Date(threat.scan_time).toLocaleTimeString()}
                  </span>
                  <div className={`activity-badge ${threat.threat_type ? threat.threat_type.toLowerCase() : 'unknown'}`}>
                    {threat.threat_type || 'UNKNOWN'}
                  </div>
                </div>
              </motion.div>
            ))
          ) : (
            <div className="empty-state">
              <CheckCircle size={48} />
              <h4>No threats detected</h4>
              <p>Your system is secure</p>
            </div>
          )}
        </div>
      </motion.div>

      {/* Quick Actions */}
      <motion.div
        className="quick-actions"
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.8 }}
      >
        <h3>Quick Actions</h3>
        <div className="actions-grid">
          <motion.button
            className="action-button primary"
            whileHover={{ scale: isScanning ? 1 : 1.02 }}
            whileTap={{ scale: isScanning ? 1 : 0.98 }}
            onClick={handleQuickScan}
            disabled={isScanning}
            style={{ opacity: isScanning ? 0.7 : 1, cursor: isScanning ? 'not-allowed' : 'pointer' }}
          >
            <Zap size={20} />
            {isScanning ? 'Scanning...' : 'Quick Scan'}
          </motion.button>
          <motion.button
            className="action-button secondary"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={handleUpdateSignatures}
          >
            <Download size={20} />
            Update Signatures
          </motion.button>
          <motion.button
            className="action-button success"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={handleToggleProtection}
          >
            <Shield size={20} />
            {systemStatus?.real_time_protection ? 'Disable Protection' : 'Enable Protection'}
          </motion.button>
          <motion.button
            className="action-button info"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={handleExportHealthReport}
          >
            <FileDown size={20} />
            Health Report
          </motion.button>
          <motion.button
            className="action-button warning"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={handleExportThreatReport}
          >
            <FileDown size={20} />
            Threat Analysis
          </motion.button>
        </div>
      </motion.div>
    </motion.div>
  );
};

export default Dashboard;