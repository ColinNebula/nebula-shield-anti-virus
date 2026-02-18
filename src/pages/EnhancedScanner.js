import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FolderOpen, File, Play, StopCircle, AlertTriangle, CheckCircle,
  Clock, Trash2, RefreshCw, Upload, HardDrive, Settings, Sparkles,
  Download, Shield, Calendar, Zap, Eye, EyeOff, Archive, Undo,
  TrendingUp, PieChart, BarChart3, Activity, Database, Lock,
  Search, Filter, AlertCircle, Info, ChevronDown, ChevronUp, X,
  Scissors
} from 'lucide-react';
import axios from 'axios';
import AntivirusAPI from '../services/antivirusApi';
import enhancedScanner from '../services/enhancedScanner';
import { useAuth } from '../contexts/AuthContext';
import notificationService from '../services/notificationService';
import virusTotalService from '../services/virusTotalService';
import pdfReportService from '../services/pdfReportService';
import toast from 'react-hot-toast';
import './EnhancedScanner.css';

// In development with React dev server, use proxy (relative URLs)
// In Electron or production, use direct backend URLs
const isElectron = typeof window !== 'undefined' && window.electronAPI?.isElectron;
const API_BASE_URL = isElectron ? 'http://localhost:8080' : '';

const EnhancedScanner = () => {
  const { checkFeatureAccess, isPremium } = useAuth();
  const [activeTab, setActiveTab] = useState('scanner'); // scanner, quarantine, schedule, statistics
  const [scanMode, setScanMode] = useState('smart'); // quick, smart, deep
  const [scanType, setScanType] = useState('file');
  const [scanPath, setScanPath] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResults, setScanResults] = useState([]);
  const [currentFile, setCurrentFile] = useState('');
  const [scanStats, setScanStats] = useState({
    totalFiles: 0,
    scannedFiles: 0,
    threatsFound: 0,
    cleanFiles: 0
  });
  
  // Real-time protection
  const [realTimeEnabled, setRealTimeEnabled] = useState(false);
  const [watchedFolders, setWatchedFolders] = useState([]);
  
  // Quarantine
  const [quarantinedFiles, setQuarantinedFiles] = useState([]);
  const [selectedQuarantineFiles, setSelectedQuarantineFiles] = useState(new Set());
  
  // Schedules
  const [schedules, setSchedules] = useState([]);
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  
  // Statistics
  const [statistics, setStatistics] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  
  // UI state
  const [expandedResult, setExpandedResult] = useState(null);
  const [filterThreatType, setFilterThreatType] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [vtReports, setVtReports] = useState(new Map());
  const [loadingVT, setLoadingVT] = useState(new Set());
  
  const fileInputRef = useRef(null);

  // Load data on mount - optimized with try-catch and lazy loading
  useEffect(() => {
    // Only load essential data initially
    loadRealTimeStatus();
    
    // Load other data lazily after a short delay to speed up initial render
    const timer = setTimeout(() => {
      loadScanHistory();
      if (activeTab === 'quarantine') loadQuarantinedFiles();
      if (activeTab === 'schedule') loadSchedules();
      if (activeTab === 'statistics') loadStatistics();
    }, 100);
    
    return () => clearTimeout(timer);
  }, []);

  // Load tab-specific data when switching tabs
  useEffect(() => {
    if (activeTab === 'quarantine') loadQuarantinedFiles();
    if (activeTab === 'schedule') loadSchedules();
    if (activeTab === 'statistics') loadStatistics();
  }, [activeTab]);

  const loadQuarantinedFiles = () => {
    try {
      const files = enhancedScanner.getQuarantinedFiles();
      setQuarantinedFiles(files);
    } catch (error) {
      console.error('Failed to load quarantine:', error);
      setQuarantinedFiles([]);
    }
  };

  const loadSchedules = () => {
    try {
      const scheduleList = enhancedScanner.getSchedules();
      setSchedules(scheduleList);
    } catch (error) {
      console.error('Failed to load schedules:', error);
      setSchedules([]);
    }
  };

  const loadStatistics = () => {
    try {
      const stats = enhancedScanner.getStatistics();
      setStatistics(stats);
    } catch (error) {
      console.error('Failed to load statistics:', error);
      setStatistics(null);
    }
  };

  const loadScanHistory = () => {
    try {
      const history = enhancedScanner.getScanHistory(10); // Reduced from 20 to 10 for faster loading
      setScanHistory(history);
    } catch (error) {
      console.error('Failed to load scan history:', error);
      setScanHistory([]);
    }
  };

  const loadRealTimeStatus = () => {
    try {
      const status = enhancedScanner.getRealTimeStatus();
      setRealTimeEnabled(status.enabled);
      setWatchedFolders(status.watchedFolders);
    } catch (error) {
      console.error('Failed to load real-time status:', error);
      setRealTimeEnabled(false);
      setWatchedFolders([]);
    }
  };

  // Handle file selection from browse button
  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    if (file) {
      setScanPath(file.path || file.name);
      toast.success(`File selected: ${file.name}`);
    }
  };

  // Scanner tab functions
  const handleScanStart = async () => {
    if (!scanPath.trim()) {
      toast.error('Please enter a path to scan');
      return;
    }

    if (scanType === 'directory') {
      const access = await checkFeatureAccess('custom-scan-paths');
      if (!access.hasAccess) {
        toast.error('Directory scanning is a Premium feature', { icon: '👑' });
        return;
      }
    }

    setIsScanning(true);
    setScanProgress(0);
    setScanResults([]);
    setCurrentFile('');
    setScanStats({ totalFiles: 0, scannedFiles: 0, threatsFound: 0, cleanFiles: 0 });

    let finalStats = null;

    try {
      const startTime = Date.now();
      let result;

      if (scanType === 'file') {
        setCurrentFile(scanPath);
        setScanProgress(50);
        
        // Call backend scanner API (port 8081 for real C++ scanner)
        try {
          console.log('[Scanner] Sending scan request:', { file_path: scanPath });
          
          const response = await axios.post('http://localhost:8081/api/scan/file', {
            file_path: scanPath
          }, {
            timeout: 30000, // 30 second timeout
            headers: {
              'Content-Type': 'application/json'
            }
          });
          
          console.log('[Scanner] Received response:', response.data);
          result = response.data;
          
          // Ensure consistent format
          result.threats = result.threats || [];
          if (result.threat_type !== 'CLEAN' && result.threat_name && result.threats.length === 0) {
            result.threats = [{
              id: result.threat_type,
              family: result.threat_name,
              severity: result.confidence > 0.8 ? 'critical' : 'high',
              detectionMethod: 'signature'
            }];
          }
          
          const normalized = normalizeScanResults(result, scanPath);
          console.log('[Scanner] Setting scan results:', normalized.results);
          setScanResults(normalized.results);
          setScanStats(normalized.stats);
          finalStats = normalized.stats;
          console.log('[Scanner] Scan stats updated');
        } catch (apiError) {
          console.error('Backend API error:', apiError);
          
          // Provide detailed error message
          let errorMsg = 'Scanner backend error';
          if (apiError.code === 'ECONNREFUSED') {
            errorMsg = 'Scanner backend not running on port 8081. Start it with: node backend/real-scanner-api.js';
          } else if (apiError.code === 'ETIMEDOUT') {
            errorMsg = 'Scanner backend timeout. The file might be too large or the server is busy.';
          } else if (apiError.response) {
            errorMsg = `Scanner error: ${apiError.response.data?.error || apiError.response.statusText}`;
          } else if (apiError.request) {
            errorMsg = 'No response from scanner backend. Check if port 8081 is accessible.';
          } else {
            errorMsg = `Scanner error: ${apiError.message}`;
          }
          
          toast.error(errorMsg, { duration: 5000 });
          throw new Error(errorMsg);
        }
      } else {
        // For directory scans, use enhanced scanner scanMultiple
        // Note: This is a simplified implementation - in production, you'd scan actual directory contents
        const mockFiles = [
          { path: scanPath, content: 'mock content for directory scan' }
        ];
        
        const scanResponse = await enhancedScanner.scanMultiple(
          mockFiles,
          (progressInfo) => {
            // Extract just the progress percentage
            setScanProgress(progressInfo.progress);
            setCurrentFile(progressInfo.currentFile);
          },
          scanMode
        );
        
        const results = scanResponse.results.map(r => ({
          file_path: r.filePath,
          threat_type: r.threats.length > 0 ? r.threats[0].id : 'CLEAN',
          threat_name: r.threats.length > 0 ? r.threats[0].family : '',
          scan_time: new Date().toISOString(),
          threats: r.threats,
          riskScore: r.riskScore
        }));
        
        setScanResults(results);

        const threats = results.filter(r => r.threat_type !== 'CLEAN');
        finalStats = {
          totalFiles: results.length,
          scannedFiles: results.length,
          threatsFound: threats.length,
          cleanFiles: results.length - threats.length
        };
        setScanStats(finalStats);
      }

      setScanProgress(100);
      
      // Add to history
      const scanDuration = Math.round((Date.now() - startTime) / 1000);
      const statsForHistory = finalStats || scanStats;
      enhancedScanner.addToHistory({
        path: scanPath,
        type: scanType,
        mode: scanMode,
        filesScanned: statsForHistory.scannedFiles,
        threatsFound: statsForHistory.threatsFound,
        duration: scanDuration
      });

      // Reload history and statistics
      loadScanHistory();
      loadStatistics();

      if (statsForHistory.threatsFound > 0) {
        toast.error(`Scan complete: ${statsForHistory.threatsFound} threats found!`);
        notificationService.showScanComplete(statsForHistory.scannedFiles, statsForHistory.threatsFound);
      } else {
        toast.success('Scan complete: No threats detected');
        notificationService.showScanComplete(statsForHistory.scannedFiles, 0);
      }

    } catch (error) {
      console.error('Scan error:', error);
      toast.error('Scan failed: ' + error.message, { duration: 5000 });
    } finally {
      setIsScanning(false);
      setCurrentFile('');
    }
  };

  const handleQuarantineFile = (result) => {
    try {
      const filePath = result.file_path || result.file || 'Unknown file';
      const threatInfo = {
        threatType: result.threat_type || result.type || 'Unknown',
        threatName: result.threat_name || result.threat || 'Unknown',
        severity: result.severity || getSeverityLevel(result.threat_type),
        fileSize: result.file_size || result.size || 0,
        hash: result.hash || ''
      };

      enhancedScanner.quarantineFile(filePath, threatInfo);
      
      toast.success(`File quarantined: ${filePath.split(/[\\/]/).pop()}`);
      loadQuarantinedFiles();
      loadStatistics();
      
      // Remove from scan results
      setScanResults(prev => prev.filter(r => 
        (r.file_path || r.file) !== filePath
      ));
    } catch (error) {
      console.error('Quarantine error:', error);
      toast.error('Failed to quarantine file: ' + error.message);
    }
  };

  const handleCleanFile = async (result) => {
    try {
      const filePath = result.file_path || result.file || 'Unknown file';
      toast.loading('Attempting to clean/repair file...', { id: 'clean-file' });
      
      const response = await AntivirusAPI.cleanFile(filePath);
      
      if (response.success) {
        // Update result to show as cleaned
        setScanResults(prev => prev.map(r => {
          const rPath = r.file_path || r.file;
          return rPath === filePath 
            ? { ...r, threat_type: 'CLEAN', cleaned: true, cleanDetails: response }
            : r;
        }));
        
        toast.success(
          `✅ File cleaned successfully! Removed ${response.signaturesRemoved || 0} threat signature(s)`,
          { id: 'clean-file', duration: 5000 }
        );
        
        loadStatistics();
      } else {
        throw new Error(response.error || 'Cleaning failed');
      }
    } catch (error) {
      const errorMsg = error.message || 'Failed to clean file';
      
      if (errorMsg.includes('Cannot clean')) {
        toast.error(
          errorMsg + '. Consider quarantining instead.',
          { id: 'clean-file', duration: 6000 }
        );
      } else {
        toast.error('❌ Failed to clean file: ' + errorMsg, { id: 'clean-file' });
      }
    }
  };

  const handleRestoreFile = (filePath) => {
    try {
      enhancedScanner.restoreFile(filePath);
      toast.success('File restored successfully');
      loadQuarantinedFiles();
      loadStatistics();
    } catch (error) {
      toast.error('Restore failed: ' + error.message);
    }
  };

  const handleDeleteFromQuarantine = (filePath) => {
    try {
      enhancedScanner.deleteFromQuarantine(filePath);
      toast.success('File deleted from quarantine');
      loadQuarantinedFiles();
      loadStatistics();
    } catch (error) {
      toast.error('Delete failed: ' + error.message);
    }
  };

  const handleToggleRealTime = () => {
    try {
      if (realTimeEnabled) {
        enhancedScanner.disableRealTimeProtection();
        toast('Real-time protection disabled', { icon: 'ℹ️' });
      } else {
        enhancedScanner.enableRealTimeProtection();
        toast.success('Real-time protection enabled');
      }
      loadRealTimeStatus();
    } catch (error) {
      toast.error('Failed to toggle protection: ' + error.message);
    }
  };

  const handleAddWatchFolder = () => {
    // Use the current scan path or default path
    const folderPath = scanPath || 'C:\\';
    
    if (!folderPath || folderPath.trim() === '') {
      toast.error('Please enter a folder path to watch in the scan path field above');
      return;
    }
    
    try {
      enhancedScanner.addWatchFolder(folderPath);
      toast.success(`Now watching: ${folderPath}`);
      loadRealTimeStatus();
    } catch (error) {
      toast.error('Failed to add folder: ' + error.message);
    }
  };

  const handleRemoveWatchFolder = (folder) => {
    try {
      enhancedScanner.removeWatchFolder(folder);
      toast(`Stopped watching: ${folder}`, { icon: 'ℹ️' });
      loadRealTimeStatus();
    } catch (error) {
      toast.error('Failed to remove folder: ' + error.message);
    }
  };

  const handleCreateSchedule = (scheduleData) => {
    try {
      enhancedScanner.createSchedule(scheduleData.name, {
        frequency: scheduleData.frequency,
        time: scheduleData.time,
        dayOfWeek: scheduleData.dayOfWeek,
        dayOfMonth: scheduleData.dayOfMonth,
        scanType: scheduleData.scanType,
        paths: scheduleData.paths
      });
      
      toast.success('Schedule created successfully');
      loadSchedules();
      setShowScheduleModal(false);
    } catch (error) {
      toast.error('Failed to create schedule: ' + error.message);
    }
  };

  const handleToggleSchedule = (id) => {
    try {
      enhancedScanner.toggleSchedule(id);
      toast.success('Schedule updated');
      loadSchedules();
    } catch (error) {
      toast.error('Failed to toggle schedule: ' + error.message);
    }
  };

  const handleDeleteSchedule = (id) => {
    try {
      enhancedScanner.deleteSchedule(id);
      toast.success('Schedule deleted');
      loadSchedules();
    } catch (error) {
      toast.error('Failed to delete schedule: ' + error.message);
    }
  };

  const getSeverityLevel = (threatType) => {
    switch (threatType) {
      case 'VIRUS': return 'critical';
      case 'MALWARE': return 'high';
      case 'SUSPICIOUS': return 'medium';
      default: return 'low';
    }
  };

  const getThreatColor = (threatType) => {
    switch (threatType) {
      case 'CLEAN': return 'success';
      case 'VIRUS': return 'danger';
      case 'MALWARE': return 'danger';
      case 'SUSPICIOUS': return 'warning';
      default: return 'warning';
    }
  };

  const getThreatIcon = (threatType) => {
    switch (threatType) {
      case 'CLEAN': return CheckCircle;
      case 'VIRUS': return AlertTriangle;
      case 'MALWARE': return AlertCircle;
      case 'SUSPICIOUS': return Info;
      default: return AlertTriangle;
    }
  };

  const getScanModeIcon = (mode) => {
    switch (mode) {
      case 'quick': return Zap;
      case 'smart': return Activity;
      case 'deep': return Search;
      default: return Activity;
    }
  };

  const normalizeScanResults = (data, fallbackPath = '') => {
    if (!data) {
      return {
        results: [],
        stats: { totalFiles: 0, scannedFiles: 0, threatsFound: 0, cleanFiles: 0 }
      };
    }

    let results = [];
    if (Array.isArray(data.results)) {
      results = data.results;
    } else if (Array.isArray(data.scanResults)) {
      results = data.scanResults;
    } else if (Array.isArray(data.files)) {
      results = data.files;
    } else if (Array.isArray(data.result)) {
      results = data.result;
    } else if (data.result && typeof data.result === 'object') {
      results = [data.result];
    } else if (data.file_path || data.threat_type || data.threat_name) {
      results = [data];
    }

    results = results.map((item) => {
      const filePath = item.file_path || item.file || item.path || fallbackPath || 'Unknown file';
      const threats = Array.isArray(item.threats) ? item.threats : [];
      const inferredType = threats[0]?.id || (item.is_clean === false ? 'MALWARE' : 'CLEAN');
      const inferredName = threats[0]?.family || '';

      return {
        ...item,
        file_path: filePath,
        threat_type: item.threat_type || item.threatType || inferredType || 'CLEAN',
        threat_name: item.threat_name || item.threatName || inferredName
      };
    });

    const threatsFound = results.filter(r => r.threat_type && r.threat_type !== 'CLEAN').length;
    const totalFiles = data.total_files ?? data.totalFiles ?? results.length;
    const cleanFiles = data.clean_files ?? data.cleanFiles ?? Math.max(0, totalFiles - threatsFound);

    return {
      results,
      stats: {
        totalFiles,
        scannedFiles: data.scanned_files ?? data.scannedFiles ?? totalFiles,
        threatsFound: data.threats_found ?? data.threatsFound ?? threatsFound,
        cleanFiles
      }
    };
  };

  const buildStatsFromStatus = (statusData) => {
    const scan = statusData?.scan || {};
    const totalFiles = scan.totalFiles ?? statusData?.totalFiles ?? 0;
    const scannedFiles = scan.scannedFiles ?? statusData?.filesScanned ?? 0;
    const threatsFound = scan.threatsFound ?? 0;
    const cleanFiles = Math.max(0, totalFiles - threatsFound);

    return {
      totalFiles,
      scannedFiles,
      threatsFound,
      cleanFiles
    };
  };

  const pollScanCompletion = async () => {
    let lastStatus = null;

    for (let attempt = 0; attempt < 300; attempt++) {
      const statusResponse = await axios.get(`${API_BASE_URL}/api/scan/status`);
      lastStatus = statusResponse.data;

      const stats = buildStatsFromStatus(lastStatus);
      const progressFromStatus = lastStatus?.progress ?? 0;
      const progress = progressFromStatus > 0
        ? progressFromStatus
        : (stats.totalFiles > 0
          ? Math.min(100, Math.round((stats.scannedFiles / stats.totalFiles) * 100))
          : 0);

      setScanProgress(progress);
      setCurrentFile(lastStatus?.scan?.currentFile || '');
      setScanStats(stats);

      if (!lastStatus?.isScanning) {
        break;
      }

      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    const resultsResponse = await axios.get(`${API_BASE_URL}/api/scan/results`);
    const normalized = normalizeScanResults(resultsResponse.data?.scan || resultsResponse.data);
    const fallbackStats = buildStatsFromStatus(lastStatus);
    const finalStats = normalized.stats.totalFiles > 0 ? normalized.stats : fallbackStats;

    setScanResults(normalized.results);
    setScanStats(finalStats);

    return { results: normalized.results, stats: finalStats };
  };

  // Filter and search results
  const filteredResults = scanResults.filter(result => {
    const matchesFilter = filterThreatType === 'all' || result.threat_type === filterThreatType;
    const filePath = result.file_path || result.file || '';
    const threatName = result.threat_name || result.threat || '';
    const matchesSearch = searchQuery === '' || 
      filePath.toLowerCase().includes(searchQuery.toLowerCase()) ||
      threatName.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  // Quick scan presets
  const quickScanOptions = [
    {
      id: 'downloads',
      title: 'Downloads',
      path: 'C:\\Users\\Public\\Downloads',
      icon: HardDrive,
      description: 'Scan downloads folder'
    },
    {
      id: 'temp',
      title: 'Temp Files',
      path: 'C:\\Windows\\Temp',
      icon: Trash2,
      description: 'Scan temporary files'
    },
    {
      id: 'startup',
      title: 'Startup',
      path: 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
      icon: Sparkles,
      description: 'Scan startup programs'
    }
  ];

  return (
    <div className="enhanced-scanner">
      {/* Header */}
      <div className="scanner-header">
        <div className="header-content">
          <div className="header-icon">
            <Shield size={48} />
          </div>
          <div className="header-text">
            <h1>
              {isScanning ? (
                <>
                  <RefreshCw size={24} className="spinning" />
                  Scanning... {scanProgress}%
                </>
              ) : (
                'Enhanced Scanner'
              )}
            </h1>
            <p>
              {isScanning 
                ? `Scanning ${currentFile || 'files'}...`
                : 'Advanced threat detection with heuristic analysis'
              }
            </p>
          </div>
        </div>

        {/* Real-time protection toggle */}
        <div className="realtime-toggle">
          <motion.button
            className={`toggle-btn ${realTimeEnabled ? 'active' : ''}`}
            onClick={handleToggleRealTime}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            {realTimeEnabled ? <Eye size={20} /> : <EyeOff size={20} />}
            <span>Real-Time Protection</span>
            <div className={`toggle-indicator ${realTimeEnabled ? 'on' : 'off'}`} />
          </motion.button>
        </div>
      </div>

      {/* Tabs */}
      <div className="scanner-tabs">
        {['scanner', 'quarantine', 'schedule', 'statistics'].map(tab => (
          <button
            key={tab}
            className={`tab-button ${activeTab === tab ? 'active' : ''}`}
            onClick={(e) => {
              e.stopPropagation();
              console.log('Tab clicked:', tab, 'Current activeTab:', activeTab);
              setActiveTab(tab);
            }}
            type="button"
          >
            {tab === 'scanner' && <Shield size={18} />}
            {tab === 'quarantine' && <Archive size={18} />}
            {tab === 'schedule' && <Calendar size={18} />}
            {tab === 'statistics' && <BarChart3 size={18} />}
            <span>{tab.charAt(0).toUpperCase() + tab.slice(1)}</span>
          </button>
        ))}
      </div>

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
            <div className="scanner-layout">
              {/* Scan Controls */}
              <div className="scan-controls">
                <h3>Scan Configuration</h3>

                {/* Scan Mode */}
                <div className="scan-mode-selector">
                  <label>Scan Mode</label>
                  <div className="mode-options">
                    {['quick', 'smart', 'deep'].map(mode => {
                      const Icon = getScanModeIcon(mode);
                      return (
                        <button
                          key={mode}
                          className={`mode-option ${scanMode === mode ? 'active' : ''}`}
                          onClick={() => setScanMode(mode)}
                          disabled={isScanning}
                        >
                          <Icon size={20} />
                          <div>
                            <strong>{mode.charAt(0).toUpperCase() + mode.slice(1)}</strong>
                            <small>
                              {mode === 'quick' && 'Fast signature scan'}
                              {mode === 'smart' && 'Adaptive scanning'}
                              {mode === 'deep' && 'Full heuristic analysis'}
                            </small>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Scan Type */}
                <div className="scan-type-selector">
                  <label>Scan Target</label>
                  <div className="type-options">
                    <button
                      className={`type-option ${scanType === 'file' ? 'active' : ''}`}
                      onClick={() => setScanType('file')}
                      disabled={isScanning}
                    >
                      <File size={18} />
                      <span>Single File</span>
                    </button>
                    <button
                      className={`type-option ${scanType === 'directory' ? 'active' : ''}`}
                      onClick={() => setScanType('directory')}
                      disabled={isScanning}
                    >
                      <FolderOpen size={18} />
                      <span>Directory</span>
                      {!isPremium && <span className="premium-badge">👑</span>}
                    </button>
                  </div>
                </div>

                {/* Path Input */}
                <div className="path-input-section">
                  <label>{scanType === 'file' ? 'File Path' : 'Directory Path'}</label>
                  <div className="path-input-group">
                    <input
                      type="text"
                      value={scanPath}
                      onChange={(e) => setScanPath(e.target.value)}
                      placeholder={scanType === 'file' ? 'C:\\path\\to\\file.exe' : 'C:\\path\\to\\directory'}
                      disabled={isScanning}
                    />
                    {scanType === 'file' && (
                      <button
                        className="browse-btn"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={isScanning}
                      >
                        <Upload size={16} />
                        Browse
                      </button>
                    )}
                  </div>
                  <input 
                    ref={fileInputRef} 
                    type="file" 
                    style={{ display: 'none' }} 
                    onChange={handleFileSelect}
                  />
                </div>

                {/* Quick Scan Options */}
                <div className="quick-scan-section">
                  <label>Quick Scan</label>
                  <div className="quick-options">
                    {quickScanOptions.map(option => {
                      const Icon = option.icon;
                      return (
                        <button
                          key={option.id}
                          className="quick-option"
                          onClick={() => {
                            setScanPath(option.path);
                            setScanType('directory');
                          }}
                          disabled={isScanning}
                        >
                          <Icon size={20} />
                          <div>
                            <strong>{option.title}</strong>
                            <small>{option.description}</small>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Scan Buttons */}
                <div className="scan-actions">
                  {!isScanning ? (
                    <>
                      <button
                        className="btn btn-success scan-btn"
                        onClick={async () => {
                          setIsScanning(true);
                          setScanProgress(0);
                          setScanResults([]);
                          setCurrentFile('');
                          setScanStats({ totalFiles: 0, scannedFiles: 0, threatsFound: 0, cleanFiles: 0 });
                          
                          try {
                            toast.loading('Starting quick scan...', { id: 'quick-scan' });
                            
                            await axios.post(`${API_BASE_URL}/api/scan/quick`, {}, {
                              timeout: 30000, // 30 second timeout
                              headers: {
                                'Content-Type': 'application/json'
                              }
                            });

                            const finalResult = await pollScanCompletion();
                            setScanProgress(100);
                            if (finalResult.stats.threatsFound > 0) {
                              toast.error(`Quick scan complete! Found ${finalResult.stats.threatsFound} threats`, { id: 'quick-scan' });
                            } else {
                              toast.success('Quick scan complete! No threats detected', { id: 'quick-scan' });
                            }
                          } catch (error) {
                            console.error('Quick scan error:', error);
                            let errorMessage = 'Quick scan failed';
                            
                            if (error.code === 'ECONNREFUSED' || error.code === 'ERR_NETWORK') {
                              errorMessage = 'Cannot connect to backend server. Please ensure the backend is running.';
                            } else if (error.response) {
                              errorMessage = error.response.data?.message || error.response.data?.error || `Server error: ${error.response.status}`;
                            } else if (error.request) {
                              errorMessage = 'No response from server. Check your connection.';
                            } else {
                              errorMessage = error.message || 'Unknown error occurred';
                            }
                            
                            toast.error(errorMessage, { id: 'quick-scan', duration: 5000 });
                          } finally {
                            setIsScanning(false);
                          }
                        }}
                      >
                        <Play size={20} />
                        Quick Scan
                      </button>

                      <button
                        className="btn btn-warning scan-btn"
                        onClick={async () => {
                          setIsScanning(true);
                          setScanProgress(0);
                          setScanResults([]);
                          setCurrentFile('');
                          setScanStats({ totalFiles: 0, scannedFiles: 0, threatsFound: 0, cleanFiles: 0 });
                          
                          try {
                            toast.loading('Starting full system scan...', { id: 'full-scan' });
                            
                            await axios.post(`${API_BASE_URL}/api/scan/full`, {}, {
                              timeout: 300000, // 5 minute timeout for full scan
                              headers: {
                                'Content-Type': 'application/json'
                              }
                            });

                            const finalResult = await pollScanCompletion();
                            setScanProgress(100);
                            if (finalResult.stats.threatsFound > 0) {
                              toast.error(`Full scan complete! Scanned ${finalResult.stats.totalFiles} files, found ${finalResult.stats.threatsFound} threats`, { id: 'full-scan' });
                            } else {
                              toast.success(`Full scan complete! Scanned ${finalResult.stats.totalFiles} files, found 0 threats`, { id: 'full-scan' });
                            }
                          } catch (error) {
                            console.error('Full scan error:', error);
                            let errorMessage = 'Full scan failed';
                            
                            if (error.code === 'ECONNREFUSED' || error.code === 'ERR_NETWORK') {
                              errorMessage = 'Cannot connect to backend server. Please ensure the backend is running.';
                            } else if (error.response) {
                              errorMessage = error.response.data?.message || error.response.data?.error || `Server error: ${error.response.status}`;
                            } else if (error.request) {
                              errorMessage = 'No response from server. Check your connection.';
                            } else {
                              errorMessage = error.message || 'Unknown error occurred';
                            }
                            
                            toast.error(errorMessage, { id: 'full-scan', duration: 5000 });
                          } finally {
                            setIsScanning(false);
                          }
                        }}
                      >
                        <HardDrive size={20} />
                        Full Scan
                      </button>

                      <button
                        className="btn btn-primary scan-btn"
                        onClick={handleScanStart}
                        disabled={!scanPath.trim()}
                      >
                        <Play size={20} />
                        Custom Scan
                      </button>
                    </>
                  ) : (
                    <button
                      className="btn btn-danger scan-btn"
                      onClick={() => setIsScanning(false)}
                    >
                      <StopCircle size={20} />
                      Stop Scan
                    </button>
                  )}
                </div>
              </div>

              {/* Scan Results */}
              <div className="scan-results">
                {/* Progress */}
                {isScanning && (
                  <div className="scan-progress-card">
                    <div className="progress-header">
                      <h4>Scanning in Progress</h4>
                      <span>{scanProgress}%</span>
                    </div>
                    <div className="progress-bar">
                      <div className="progress-fill" style={{ width: `${scanProgress}%` }} />
                    </div>
                    {currentFile && (
                      <div className="current-file">
                        <File size={14} />
                        <span>{currentFile}</span>
                      </div>
                    )}
                    <div className="scan-stats-inline">
                      <div><span>{scanStats.scannedFiles}</span> Scanned</div>
                      <div><span>{scanStats.cleanFiles}</span> Clean</div>
                      <div><span className="threat">{scanStats.threatsFound}</span> Threats</div>
                    </div>
                  </div>
                )}

                {/* Results List */}
                {scanResults.length > 0 && (
                  <>
                    <div className="results-header">
                      <h3>Scan Results ({filteredResults.length})</h3>
                      <div className="results-actions">
                        <div className="search-box">
                          <Search size={16} />
                          <input
                            type="text"
                            placeholder="Search results..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                          />
                        </div>
                        <select
                          value={filterThreatType}
                          onChange={(e) => setFilterThreatType(e.target.value)}
                          className="filter-select"
                        >
                          <option value="all">All Types</option>
                          <option value="VIRUS">Viruses</option>
                          <option value="MALWARE">Malware</option>
                          <option value="SUSPICIOUS">Suspicious</option>
                          <option value="CLEAN">Clean</option>
                        </select>
                        <button
                          className="btn btn-sm btn-close-results"
                          onClick={() => {
                            setScanResults([]);
                            setSearchQuery('');
                            setFilterThreatType('all');
                          }}
                          title="Clear results"
                        >
                          <X size={18} />
                        </button>
                      </div>
                    </div>

                    <div className="results-list">
                      {filteredResults.map((result, index) => {
                        const Icon = getThreatIcon(result.threat_type);
                        const color = getThreatColor(result.threat_type);
                        const isExpanded = expandedResult === index;
                        const filePath = result.file_path || result.file || 'Unknown file';
                        const fileName = filePath.split(/[\\/]/).pop();

                        return (
                          <motion.div
                            key={index}
                            className={`result-card ${color}`}
                            initial={{ opacity: 0, x: -20 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: index * 0.05 }}
                          >
                            <div className="result-main">
                              <div className={`result-icon ${color}`}>
                                <Icon size={24} />
                              </div>
                              <div className="result-info">
                                <h4>{fileName}</h4>
                                <p className="file-path">{filePath}</p>
                                <div className="result-meta">
                                  <span className={`threat-badge ${color}`}>
                                    {result.threat_type}
                                  </span>
                                  {result.threat_name && (
                                    <span className="threat-name">{result.threat_name}</span>
                                  )}
                                  <span className="file-size">
                                    {((result.file_size || 0) / 1024).toFixed(1)} KB
                                  </span>
                                </div>
                              </div>
                              <div className="result-actions">
                                {result.threat_type !== 'CLEAN' && (
                                  <>
                                    <button
                                      className="btn btn-sm btn-success"
                                      onClick={() => handleCleanFile(result)}
                                      title="Attempt to clean/repair file"
                                      style={{ marginRight: '0.5rem' }}
                                    >
                                      <Scissors size={16} />
                                      Clean/Repair
                                    </button>
                                    <button
                                      className="btn btn-sm btn-warning"
                                      onClick={() => handleQuarantineFile(result)}
                                      title="Move to quarantine"
                                    >
                                      <Archive size={16} />
                                      Quarantine
                                    </button>
                                  </>
                                )}
                                {result.cleaned && (
                                  <span className="badge badge-success" style={{ marginRight: '0.5rem' }}>
                                    ✓ Cleaned
                                  </span>
                                )}
                                <button
                                  className="btn btn-sm btn-secondary"
                                  onClick={() => setExpandedResult(isExpanded ? null : index)}
                                >
                                  {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                                  Details
                                </button>
                              </div>
                            </div>

                            {/* Expanded Details */}
                            {isExpanded && result.heuristicAnalysis && (
                              <motion.div
                                className="result-details"
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: 'auto', opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                              >
                                <h5>Heuristic Analysis</h5>
                                <div className="heuristic-info">
                                  <div className="suspicion-score">
                                    <label>Suspicion Score</label>
                                    <div className="score-bar">
                                      <div 
                                        className="score-fill" 
                                        style={{ 
                                          width: `${result.heuristicAnalysis.suspicionScore}%`,
                                          backgroundColor: result.heuristicAnalysis.risk === 'critical' ? '#ef4444' :
                                                          result.heuristicAnalysis.risk === 'high' ? '#fb923c' :
                                                          result.heuristicAnalysis.risk === 'medium' ? '#eab308' : '#60a5fa'
                                        }} 
                                      />
                                    </div>
                                    <span>{result.heuristicAnalysis.suspicionScore}/100</span>
                                  </div>
                                  {result.heuristicAnalysis.indicators && result.heuristicAnalysis.indicators.length > 0 && (
                                    <div className="indicators-list">
                                      <label>Detected Indicators</label>
                                      {result.heuristicAnalysis.indicators.map((indicator, idx) => (
                                        <div key={idx} className="indicator-item">
                                          <AlertCircle size={14} />
                                          <span>{indicator.description}</span>
                                          <span className="indicator-score">+{indicator.score}</span>
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                  <div className="recommendation">
                                    <Info size={16} />
                                    <span>{result.heuristicAnalysis.recommendation}</span>
                                  </div>
                                </div>
                              </motion.div>
                            )}
                          </motion.div>
                        );
                      })}
                    </div>
                  </>
                )}

                {/* Empty State */}
                {!isScanning && scanResults.length === 0 && (
                  <div className="empty-state">
                    <Shield size={64} />
                    <h3>No Scan Results</h3>
                    <p>Configure your scan and click "Start Scan" to begin</p>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'quarantine' && (
          <motion.div
            key="quarantine"
            className="tab-content"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <div className="quarantine-section">
              <div className="section-header">
                <h3>
                  <Archive size={24} />
                  Quarantine ({quarantinedFiles.length} files)
                </h3>
                <button
                  className="btn btn-danger btn-sm"
                  onClick={() => {
                    selectedQuarantineFiles.forEach(path => handleDeleteFromQuarantine(path));
                    setSelectedQuarantineFiles(new Set());
                  }}
                  disabled={selectedQuarantineFiles.size === 0}
                >
                  <Trash2 size={16} />
                  Delete Selected ({selectedQuarantineFiles.size})
                </button>
              </div>

              {quarantinedFiles.length > 0 ? (
                <div className="quarantine-list">
                  {quarantinedFiles.map((file, index) => (
                    <div key={file.id} className="quarantine-item">
                      <input
                        type="checkbox"
                        checked={selectedQuarantineFiles.has(file.originalPath)}
                        onChange={(e) => {
                          const newSet = new Set(selectedQuarantineFiles);
                          if (e.target.checked) {
                            newSet.add(file.originalPath);
                          } else {
                            newSet.delete(file.originalPath);
                          }
                          setSelectedQuarantineFiles(newSet);
                        }}
                      />
                      <Lock size={20} className="quarantine-icon" />
                      <div className="quarantine-info">
                        <h4>{file.originalPath.split(/[\\/]/).pop()}</h4>
                        <p>{file.originalPath}</p>
                        <div className="quarantine-meta">
                          <span className={`severity-badge ${file.severity}`}>
                            {file.severity}
                          </span>
                          <span>{file.threatType} - {file.threatName}</span>
                          <span>{((file.fileSize || 0) / 1024).toFixed(1)} KB</span>
                          <span>
                            <Clock size={12} />
                            {new Date(file.quarantineDate).toLocaleString()}
                          </span>
                        </div>
                      </div>
                      <div className="quarantine-actions">
                        {file.canRestore && (
                          <button
                            className="btn btn-sm btn-success"
                            onClick={() => handleRestoreFile(file.originalPath)}
                          >
                            <Undo size={14} />
                            Restore
                          </button>
                        )}
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={() => handleDeleteFromQuarantine(file.originalPath)}
                        >
                          <Trash2 size={14} />
                          Delete
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <Archive size={64} />
                  <h3>No Quarantined Files</h3>
                  <p>Infected files will appear here when quarantined</p>
                </div>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === 'schedule' && (
          <motion.div
            key="schedule"
            className="tab-content"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <div className="schedule-section">
              <div className="section-header">
                <h3>
                  <Calendar size={24} />
                  Scheduled Scans ({schedules.length})
                </h3>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => setShowScheduleModal(true)}
                >
                  <Calendar size={16} />
                  Create Schedule
                </button>
              </div>

              {schedules.length > 0 ? (
                <div className="schedule-list">
                  {schedules.map(schedule => (
                    <div key={schedule.id} className={`schedule-item ${!schedule.enabled ? 'disabled' : ''}`}>
                      <div className="schedule-icon">
                        <Calendar size={24} />
                      </div>
                      <div className="schedule-info">
                        <h4>{schedule.name}</h4>
                        <div className="schedule-meta">
                          <span>
                            <Clock size={14} />
                            {schedule.frequency} at {schedule.time}
                          </span>
                          <span>{schedule.scanType} scan</span>
                          <span>Next: {new Date(schedule.nextRun).toLocaleString()}</span>
                        </div>
                      </div>
                      <div className="schedule-actions">
                        <button
                          className={`btn btn-sm ${schedule.enabled ? 'btn-warning' : 'btn-success'}`}
                          onClick={() => handleToggleSchedule(schedule.id)}
                        >
                          {schedule.enabled ? 'Pause' : 'Resume'}
                        </button>
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={() => handleDeleteSchedule(schedule.id)}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <Calendar size={64} />
                  <h3>No Scheduled Scans</h3>
                  <p>Create a schedule to automate regular scans</p>
                </div>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === 'statistics' && statistics && (
          <motion.div
            key="statistics"
            className="tab-content"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
          >
            <div className="statistics-section">
              <h3>
                <BarChart3 size={24} />
                Scanner Statistics
              </h3>

              {/* Stats Grid */}
              <div className="stats-grid">
                <div className="stat-card">
                  <TrendingUp size={32} className="stat-icon" />
                  <div className="stat-value">{statistics.totalScans}</div>
                  <div className="stat-label">Total Scans</div>
                </div>
                <div className="stat-card">
                  <AlertTriangle size={32} className="stat-icon danger" />
                  <div className="stat-value">{statistics.totalThreats}</div>
                  <div className="stat-label">Threats Detected</div>
                </div>
                <div className="stat-card">
                  <Database size={32} className="stat-icon" />
                  <div className="stat-value">{statistics.totalFilesScanned.toLocaleString()}</div>
                  <div className="stat-label">Files Scanned</div>
                </div>
                <div className="stat-card">
                  <Archive size={32} className="stat-icon warning" />
                  <div className="stat-value">{statistics.quarantineStats.totalFiles}</div>
                  <div className="stat-label">Quarantined</div>
                </div>
              </div>

              {/* Threats by Type */}
              {Object.keys(statistics.threatsByType).length > 0 && (
                <div className="threats-by-type">
                  <h4>Threats by Type</h4>
                  <div className="threat-type-chart">
                    {Object.entries(statistics.threatsByType).map(([type, count]) => (
                      <div key={type} className="threat-type-bar">
                        <span className="type-name">{type}</span>
                        <div className="bar-container">
                          <div 
                            className="bar-fill" 
                            style={{ 
                              width: `${(count / statistics.totalThreats) * 100}%`,
                              backgroundColor: '#3b82f6'
                            }} 
                          />
                        </div>
                        <span className="type-count">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recent Scan History */}
              {scanHistory.length > 0 && (
                <div className="recent-scans">
                  <h4>Recent Scans</h4>
                  <div className="history-list">
                    {scanHistory.slice(0, 10).map((scan, index) => (
                      <div key={scan.id} className="history-item">
                        <Clock size={16} />
                        <div className="history-info">
                          <strong>{scan.path}</strong>
                          <div className="history-meta">
                            <span>{new Date(scan.timestamp).toLocaleString()}</span>
                            <span>{scan.filesScanned} files</span>
                            <span>{scan.threatsFound} threats</span>
                            <span>{scan.duration}s</span>
                            <span className="scan-mode">{scan.mode}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Real-time Protection Panel */}
      {realTimeEnabled && (
        <motion.div
          className="realtime-panel"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="panel-header">
            <h4>
              <Eye size={20} />
              Real-Time Protection Active
            </h4>
            <button className="btn btn-sm btn-secondary" onClick={handleAddWatchFolder}>
              Add Folder
            </button>
          </div>
          <div className="watched-folders">
            {watchedFolders.length > 0 ? (
              watchedFolders.map((folder, index) => (
                <div key={index} className="watched-folder">
                  <FolderOpen size={16} />
                  <span>{folder}</span>
                  <button
                    className="remove-btn"
                    onClick={() => handleRemoveWatchFolder(folder)}
                  >
                    <X size={14} />
                  </button>
                </div>
              ))
            ) : (
              <p>No folders being watched. Add folders to monitor for threats.</p>
            )}
          </div>
        </motion.div>
      )}

      {/* Schedule Modal */}
      {showScheduleModal && (
        <div className="modal-overlay" onClick={() => setShowScheduleModal(false)}>
          <motion.div
            className="modal-content schedule-modal"
            onClick={(e) => e.stopPropagation()}
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
          >
            <div className="modal-header">
              <h3>
                <Calendar size={24} />
                Create Scheduled Scan
              </h3>
              <button className="close-btn" onClick={() => setShowScheduleModal(false)}>
                <X size={20} />
              </button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Schedule Name</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="Daily System Scan"
                />
              </div>
              <div className="form-group">
                <label>Scan Type</label>
                <select className="form-select">
                  <option value="quick">Quick Scan</option>
                  <option value="smart">Smart Scan</option>
                  <option value="deep">Deep Scan</option>
                </select>
              </div>
              <div className="form-group">
                <label>Scan Path</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="C:\Users"
                />
              </div>
              <div className="form-group">
                <label>Frequency</label>
                <select className="form-select">
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
              <div className="form-group">
                <label>Time</label>
                <input
                  type="time"
                  className="form-input"
                  defaultValue="02:00"
                />
              </div>
            </div>
            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={() => setShowScheduleModal(false)}
              >
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={() => {
                  toast.success('Schedule created successfully!');
                  setShowScheduleModal(false);
                }}
              >
                Create Schedule
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
};

export default EnhancedScanner;
