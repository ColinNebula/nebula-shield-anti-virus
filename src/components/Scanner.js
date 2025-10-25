import React, { useState, useRef, useMemo, useCallback, memo, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FolderOpen,
  File,
  Play,
  StopCircle,
  AlertTriangle,
  CheckCircle,
  Clock,
  Trash2,
  RefreshCw,
  Upload,
  HardDrive,
  Settings,
  Sparkles,
  Download,
  Shield
} from 'lucide-react';
import AntivirusAPI from '../services/antivirusApi';
import { useAuth } from '../contexts/AuthContext';
import notificationService from '../services/notificationService';
import toast from 'react-hot-toast';
import './Scanner.css';

const Scanner = memo(() => {
  const { checkFeatureAccess, isPremium } = useAuth();
  const [scanType, setScanType] = useState('file'); // 'file' or 'directory'
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
  const [scanHistory, setScanHistory] = useState([]);
  const [vtReports, setVtReports] = useState(new Map());
  const [loadingVT, setLoadingVT] = useState(new Set());
  const fileInputRef = useRef(null);
  const scanWorkerRef = useRef(null);

  // OPTIMIZATION: Load cached scan history from IndexedDB
  useEffect(() => {
    const loadCachedHistory = async () => {
      try {
        const { default: scanCache } = await import('../services/scanCache');
        const cached = await scanCache.getRecentScans(20);
        if (cached && cached.length > 0) {
          setScanHistory(cached);
        }
      } catch (error) {
        console.warn('Cache not available:', error);
      }
    };
    loadCachedHistory();
  }, []);

  // OPTIMIZATION: Memoize filtered and computed values
  const threatResults = useMemo(() => {
    return scanResults.filter(result => result.threat_type !== 'CLEAN');
  }, [scanResults]);

  const threatSummary = useMemo(() => {
    const summary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };
    threatResults.forEach(result => {
      const severity = result.severity?.toLowerCase() || 'low';
      if (severity in summary) {
        summary[severity]++;
      }
    });
    return summary;
  }, [threatResults]);

  // OPTIMIZATION: Memoize handleScanStart callback
  const handleScanStart = useCallback(async () => {
    if (!scanPath.trim()) {
      toast.error('Please enter a path to scan');
      return;
    }

    // Check for premium feature access for directory scans
    if (scanType === 'directory') {
      const access = await checkFeatureAccess('custom-scan-paths');
      if (!access.hasAccess) {
        toast.error('Directory scanning is a Premium feature. Upgrade to unlock!', {
          duration: 4000,
          icon: '👑'
        });
        return;
      }
    }

    setIsScanning(true);
    setScanProgress(0);
    setScanResults([]);
    setCurrentFile('');
    setScanStats({
      totalFiles: 0,
      scannedFiles: 0,
      threatsFound: 0,
      cleanFiles: 0
    });

    try {
      let result;
      const startTime = Date.now();

      if (scanType === 'file') {
        // Simulate progress for file scan
        setCurrentFile(scanPath);
        setScanProgress(50);
        
        result = await AntivirusAPI.scanFile(scanPath);
        setScanResults([result]);
        
        setScanStats({
          totalFiles: 1,
          scannedFiles: 1,
          threatsFound: result.threat_type !== 'CLEAN' ? 1 : 0,
          cleanFiles: result.threat_type === 'CLEAN' ? 1 : 0
        });
      } else {
        // Directory scan with simulated progress
        result = await AntivirusAPI.scanDirectory(scanPath, true);
        setScanResults(result.results || []);
        
        const threats = result.results?.filter(r => r.threat_type !== 'CLEAN') || [];
        const clean = result.results?.filter(r => r.threat_type === 'CLEAN') || [];
        
        setScanStats({
          totalFiles: result.results?.length || 0,
          scannedFiles: result.results?.length || 0,
          threatsFound: threats.length,
          cleanFiles: clean.length
        });
      }

      setScanProgress(100);
      
      // Add to scan history
      const endTime = Date.now();
      const scanDuration = Math.round((endTime - startTime) / 1000);
      
      const historyEntry = {
        id: Date.now(),
        path: scanPath,
        type: scanType,
        timestamp: new Date().toLocaleString(),
        duration: scanDuration,
        results: result.results?.length || 1,
        threats: scanStats.threatsFound
      };
      
      setScanHistory(prev => [historyEntry, ...prev.slice(0, 9)]); // Keep last 10 scans

      // OPTIMIZATION: Cache scan result to IndexedDB for offline access
      try {
        const { default: scanCache } = await import('../services/scanCache');
        await scanCache.cacheScanResult({
          path: scanPath,
          type: scanType,
          results: scanResults,
          stats: scanStats,
          duration: scanDuration,
          timestamp: Date.now()
        });
      } catch (error) {
        console.warn('Failed to cache scan result:', error);
      }

      // Show notifications
      if (scanStats.threatsFound > 0) {
        toast.error(`Scan complete: ${scanStats.threatsFound} threats found!`);
        notificationService.showScanComplete(scanStats.scannedFiles, scanStats.threatsFound);
      } else {
        toast.success('Scan complete: No threats detected');
        notificationService.showScanComplete(scanStats.scannedFiles, 0);
      }

    } catch (error) {
      console.error('Scan error details:', error);
      
      // More specific error messages
      let errorMsg = 'Scan failed';
      if (error.message.includes('JSON')) {
        errorMsg = 'Backend response error. Please refresh the page (Ctrl+Shift+R) and try again.';
      } else if (error.message.includes('HTTP')) {
        errorMsg = 'Could not connect to backend. Please ensure the C++ backend is running.';
      } else if (error.message.includes('fetch')) {
        errorMsg = 'Network error. Check if backend is running on port 8080.';
      } else {
        errorMsg = 'Scan failed: ' + error.message;
      }
      
      toast.error(errorMsg, { duration: 5000 });
    } finally {
      setIsScanning(false);
      setCurrentFile('');
    }
  }, [scanPath, scanType, checkFeatureAccess, scanResults, scanStats]);

  // OPTIMIZATION: Memoize handleScanStop callback
  const handleScanStop = useCallback(() => {
    if (scanWorkerRef.current) {
      scanWorkerRef.current.postMessage({ type: 'CANCEL_SCAN' });
    }
    setIsScanning(false);
    setScanProgress(0);
    setCurrentFile('');
    toast('Scan stopped', { icon: 'ℹ️' });
  }, []);

  // OPTIMIZATION: Memoize VirusTotal check with lazy loading
  const handleCheckVirusTotal = useCallback(async (filePath) => {
    setLoadingVT(prev => new Set(prev).add(filePath));
    const loadingToast = toast.loading('🔍 Checking VirusTotal...');
    
    try {
      // Lazy load VirusTotal service
      const { default: virusTotalService } = await import('../services/virusTotalService');
      const report = await virusTotalService.checkFile(filePath);
      
      toast.dismiss(loadingToast);
      
      if (report.found) {
        const badge = virusTotalService.getReputationBadge(report.reputation);
        setVtReports(prev => new Map(prev).set(filePath, report));
        
        if (report.reputation === 'malicious') {
          toast.error(`⚠️ ${report.detectionRatio} vendors flagged this file!`, {
            duration: 5000,
          });
        } else if (report.reputation === 'suspicious') {
          toast(`⚠️ ${report.detectionRatio} detections - ${badge.text}`, {
            icon: badge.icon,
            duration: 4000,
          });
        } else {
          toast.success(`✓ File reputation: ${badge.text} (${report.detectionRatio})`, {
            duration: 4000,
          });
        }
      } else {
        toast('File not found in VirusTotal database', {
          icon: 'ℹ️',
          duration: 3000,
        });
      }
    } catch (error) {
      toast.dismiss(loadingToast);
      toast.error('VirusTotal check failed: ' + error.message);
      console.error('VirusTotal error:', error);
    } finally {
      setLoadingVT(prev => {
        const newSet = new Set(prev);
        newSet.delete(filePath);
        return newSet;
      });
    }
  }, []);

  // OPTIMIZATION: Memoize handleCleanFile callback
  const handleCleanFile = useCallback(async (filePath) => {
    const loadingToast = toast.loading('🧹 Analyzing and cleaning file...');
    
    try {
      const result = await AntivirusAPI.cleanFile(filePath);
      
      toast.dismiss(loadingToast);
      
      if (result.success) {
        // Enhanced success message with more details
        const details = [];
        if (result.signaturesRemoved) details.push(`${result.signaturesRemoved} signature(s) removed`);
        if (result.integrityVerified) details.push('integrity verified ✓');
        if (result.fileType) details.push(`${result.fileType}`);
        
        toast.success(
          `✨ File cleaned successfully!\n${details.join(' • ')}\n💾 Backup: ${result.backupPath || filePath + '.backup'}`,
          { duration: 6000 }
        );
        
        // Update scan results to mark file as cleaned
        setScanResults(prevResults => 
          prevResults.map(r => 
            r.file_path === filePath 
              ? { ...r, threat_type: 'CLEAN', threat_name: 'Cleaned ✓' }
              : r
          )
        );
      } else {
        // Enhanced error message with recommendations
        const errorMsg = result.error || 'Unknown error';
        const recommendation = result.recommendation === 'QUARANTINE' 
          ? '\n⚠️ Recommendation: Use quarantine instead'
          : '';
        
        toast.error(`❌ Failed to clean file: ${errorMsg}${recommendation}`, {
          duration: 6000
        });
      }
    } catch (error) {
      toast.dismiss(loadingToast);
      
      // Check if it's a 400 error (file type not suitable for cleaning)
      if (error.message.includes('400') || error.message.includes('Cannot clean')) {
        toast.error(`⛔ ${error.message}\n💡 Tip: Use quarantine for executables and archives`, {
          duration: 6000
        });
      } else {
        toast.error('❌ File cleaning failed: ' + error.message);
      }
      
      console.error('Clean file error:', error);
    }
  }, []);

  // OPTIMIZATION: Memoize file selection callbacks
  const handleFileSelect = useCallback(() => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  }, []);

  const handleFileChange = useCallback((event) => {
    const file = event.target.files[0];
    if (file) {
      setScanPath(file.name);
      setScanType('file');
    }
  }, []);

  // OPTIMIZATION: Memoize PDF export with lazy loading
  const handleExportPDF = useCallback(async () => {
    if (scanResults.length === 0) {
      toast.error('No scan results to export');
      return;
    }

    // Check for premium feature access for advanced PDF reports
    const access = await checkFeatureAccess('advanced-reports');
    if (!access.hasAccess) {
      toast.error('Advanced PDF reports are a Premium feature. Upgrade to unlock!', {
        duration: 4000,
        icon: '👑'
      });
      return;
    }

    const loadingToast = toast.loading('📄 Generating PDF report...');

    try {
      // Lazy load PDF service
      const { default: pdfReportService } = await import('../services/pdfReportService');
      const scanData = {
        scanDate: Date.now(),
        scanType: scanType === 'file' ? 'File Scan' : 'Directory Scan',
        filesScanned: scanStats.scannedFiles,
        threatsDetected: scanStats.threatsFound,
        duration: scanHistory[0]?.duration || 0,
        status: 'Completed',
        threats: scanResults
          .filter(r => r.threat_type !== 'CLEAN')
          .map(r => ({
            file: r.file_path,
            type: r.threat_type,
            severity: r.threat_type === 'VIRUS' ? 'High' : 'Medium',
            action: 'Detected'
          }))
      };

      await pdfReportService.downloadScanReport(
        scanData,
        `scan-report-${new Date().toISOString().split('T')[0]}.pdf`
      );

      toast.dismiss(loadingToast);
      toast.success('✅ PDF report downloaded successfully!');
    } catch (error) {
      toast.dismiss(loadingToast);
      toast.error('Failed to generate PDF: ' + error.message);
      console.error('PDF generation error:', error);
    }
  }, [scanResults, checkFeatureAccess, scanType, scanStats, scanHistory]);

  // Detect platform using browser APIs
  const isWindows = navigator.platform.toLowerCase().includes('win');
  
  // OPTIMIZATION: Memoize quick scan callback
  const handleQuickSystemScan = useCallback(async () => {
    setScanType('directory');
    setScanPath(isWindows ? 'C:\\' : '/');
    
    toast.info('Starting Quick System Scan...', {
      icon: '⚡',
      duration: 2000
    });
    
    // Trigger scan
    setTimeout(() => {
      handleScanStart();
    }, 500);
  }, [isWindows, handleScanStart]);

  const handleFullSystemScan = async () => {
    // Check for premium feature access for full system scan
    const access = await checkFeatureAccess('custom-scan-paths');
    if (!access.hasAccess) {
      toast.error('Full System Scan is a Premium feature. Upgrade to unlock!', {
        duration: 4000,
        icon: '👑'
      });
      return;
    }

    setScanType('directory');
    setScanPath(isWindows ? 'C:\\' : '/');
    
    toast.info('Starting Full System Scan... This may take a while.', {
      icon: '🔍',
      duration: 3000
    });
    
    // Trigger scan
    setTimeout(() => {
      handleScanStart();
    }, 500);
  };
  
  const quickScanOptions = [
    {
      id: 'downloads',
      title: 'Downloads Folder',
      path: isWindows ? 'C:\\Users\\Public\\Downloads' : '~/Downloads',
      icon: Download,
      description: 'Scan your downloads folder for threats'
    },
    {
      id: 'system',
      title: 'System Files',
      path: isWindows ? 'C:\\Windows\\System32' : '/usr/bin',
      icon: Settings,
      description: 'Quick scan of critical system files'
    },
    {
      id: 'temp',
      title: 'Temporary Files',
      path: isWindows ? 'C:\\Windows\\Temp' : '/tmp',
      icon: Trash2,
      description: 'Scan temporary files and folders'
    }
  ];

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
      case 'MALWARE': return AlertTriangle;
      case 'SUSPICIOUS': return AlertTriangle;
      default: return AlertTriangle;
    }
  };

  return (
    <motion.div
      className="scanner"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      {/* Page Header - Dynamic */}
      <div className="page-header">
        <motion.h1
          className="page-title"
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.1 }}
        >
          {isScanning ? (
            <>
              <RefreshCw size={24} className="spinning" style={{ marginRight: '12px' }} />
              Scanning... {scanProgress}%
            </>
          ) : (
            'Scanner'
          )}
        </motion.h1>
        <motion.p
          className="page-subtitle"
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
        >
          {isScanning ? (
            `Scanning ${currentFile || 'files'}...`
          ) : scanResults.length > 0 ? (
            `Last scan: ${scanResults.length} files scanned, ${scanResults.filter(r => r.threat_type !== 'CLEAN').length} threats found`
          ) : (
            'Scan files and directories for threats'
          )}
        </motion.p>
      </div>

      <div className="scanner-layout">
        {/* Scan Controls */}
        <motion.div
          className="scan-controls"
          initial={{ x: -20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ delay: 0.3 }}
        >
          <div className="control-header">
            <h3>Scan Configuration</h3>
          </div>

          {/* Scan Type Selection */}
          <div className="scan-type-selector">
            <div className="type-options">
              <motion.button
                className={`type-option ${scanType === 'file' ? 'active' : ''}`}
                onClick={() => setScanType('file')}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <File size={20} />
                <span>Single File</span>
              </motion.button>
              <motion.button
                className={`type-option ${scanType === 'directory' ? 'active' : ''}`}
                onClick={() => setScanType('directory')}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <FolderOpen size={20} />
                <span>Directory</span>
                {!isPremium && <span className="premium-badge">👑 Premium</span>}
              </motion.button>
            </div>
          </div>

          {/* Path Input */}
          <div className="path-input-section">
            <label htmlFor="scanPath">
              {scanType === 'file' ? 'File Path' : 'Directory Path'}
            </label>
            <div className="path-input-group">
              <input
                id="scanPath"
                type="text"
                className="input path-input"
                placeholder={scanType === 'file' ? 'Enter file path...' : 'Enter directory path...'}
                value={scanPath}
                onChange={(e) => setScanPath(e.target.value)}
                disabled={isScanning}
              />
              {scanType === 'file' && (
                <motion.button
                  className="btn btn-secondary browse-btn"
                  onClick={handleFileSelect}
                  disabled={isScanning}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <Upload size={16} />
                  Browse
                </motion.button>
              )}
            </div>
            <input
              ref={fileInputRef}
              type="file"
              style={{ display: 'none' }}
              onChange={handleFileChange}
            />
          </div>

          {/* System Scan Buttons */}
          <div className="system-scan-section">
            <h4>System Scans</h4>
            <div className="system-scan-buttons">
              <motion.button
                className="system-scan-btn quick-scan-btn"
                onClick={handleQuickSystemScan}
                disabled={isScanning}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <div className="scan-btn-icon">
                  <RefreshCw size={24} />
                </div>
                <div className="scan-btn-content">
                  <h5>Quick Scan</h5>
                  <p>Scan critical system areas (~5 min)</p>
                </div>
              </motion.button>
              
              <motion.button
                className="system-scan-btn full-scan-btn"
                onClick={handleFullSystemScan}
                disabled={isScanning}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <div className="scan-btn-icon">
                  <HardDrive size={24} />
                </div>
                <div className="scan-btn-content">
                  <h5>Full System Scan</h5>
                  <p>Complete system scan (~30+ min)</p>
                  {!isPremium && <span className="premium-badge-inline">👑 Premium</span>}
                </div>
              </motion.button>
            </div>
          </div>

          {/* Quick Scan Options */}
          <div className="quick-scan-section">
            <h4>Folder Shortcuts</h4>
            <div className="quick-options">
              {quickScanOptions.map((option) => {
                const Icon = option.icon;
                return (
                  <motion.button
                    key={option.id}
                    className="quick-option"
                    onClick={() => {
                      setScanPath(option.path);
                      setScanType('directory');
                    }}
                    disabled={isScanning}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    <Icon size={20} />
                    <div className="option-content">
                      <h5>{option.title}</h5>
                      <p>{option.description}</p>
                    </div>
                  </motion.button>
                );
              })}
            </div>
          </div>

          {/* Scan Controls */}
          <div className="scan-actions">
            {!isScanning ? (
              <motion.button
                className="btn btn-primary scan-btn"
                onClick={handleScanStart}
                disabled={!scanPath.trim()}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <Play size={20} />
                Start Custom Scan
              </motion.button>
            ) : (
              <motion.button
                className="btn btn-danger scan-btn"
                onClick={handleScanStop}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <StopCircle size={20} />
                Stop Scan
              </motion.button>
            )}
          </div>
        </motion.div>

        {/* Scan Progress and Results */}
        <div className="scan-content">
          {/* Progress Section */}
          <AnimatePresence>
            {isScanning && (
              <motion.div
                className="scan-progress-section"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
              >
                <div className="progress-header">
                  <h3>Scanning in Progress...</h3>
                  <span className="progress-percentage">{scanProgress}%</span>
                </div>
                <div className="progress-bar">
                  <motion.div
                    className="progress-fill"
                    initial={{ width: 0 }}
                    animate={{ width: `${scanProgress}%` }}
                    transition={{ duration: 0.5 }}
                  />
                </div>
                {currentFile && (
                  <div className="current-file">
                    <File size={16} />
                    <span>{currentFile}</span>
                  </div>
                )}
                <div className="scan-stats-grid">
                  <div className="stat-item">
                    <span className="stat-value">{scanStats.scannedFiles}</span>
                    <span className="stat-label">Scanned</span>
                  </div>
                  <div className="stat-item">
                    <span className="stat-value">{scanStats.cleanFiles}</span>
                    <span className="stat-label">Clean</span>
                  </div>
                  <div className="stat-item">
                    <span className="stat-value threat">{scanStats.threatsFound}</span>
                    <span className="stat-label">Threats</span>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Results Section */}
          {scanResults.length > 0 && (
            <motion.div
              className="scan-results-section"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <div className="results-header">
                <h3>Scan Results</h3>
                <div className="results-actions">
                  <motion.button
                    className="btn btn-secondary btn-sm"
                    onClick={handleExportPDF}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Download size={14} />
                    Export PDF
                    {!isPremium && <span className="premium-badge-inline">👑</span>}
                  </motion.button>
                  <span className="results-count">{scanResults.length} items</span>
                </div>
              </div>
              <div className="results-list">
                {scanResults.map((result, index) => {
                  const ThreatIcon = getThreatIcon(result.threat_type);
                  const threatColor = getThreatColor(result.threat_type);
                  
                  return (
                    <motion.div
                      key={index}
                      className={`result-item ${threatColor}`}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 }}
                    >
                      <div className={`result-icon ${threatColor}`}>
                        <ThreatIcon size={20} />
                      </div>
                      <div className="result-content">
                        <h4>{result.file_path}</h4>
                        <div className="result-meta">
                          <span className={`threat-type ${threatColor}`}>
                            {result.threat_type}
                          </span>
                          {result.threat_name && (
                            <span className="threat-name">{result.threat_name}</span>
                          )}
                          <span className="file-size">
                            {(result.file_size / 1024).toFixed(1)} KB
                          </span>
                          {vtReports.has(result.file_path) && (() => {
                            const report = vtReports.get(result.file_path);
                            const badge = virusTotalService.getReputationBadge(report.reputation);
                            return (
                              <span 
                                className="vt-badge" 
                                style={{ color: badge.color }}
                                title={`${badge.description} - ${report.detectionRatio}`}
                              >
                                <Shield size={12} />
                                {report.detectionRatio}
                              </span>
                            );
                          })()}
                        </div>
                      </div>
                      <div className="result-actions">
                        <motion.button
                          className="btn btn-info btn-sm"
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                          onClick={() => handleCheckVirusTotal(result.file_path)}
                          disabled={loadingVT.has(result.file_path)}
                          title="Check file reputation on VirusTotal"
                        >
                          <Shield size={14} />
                          {loadingVT.has(result.file_path) ? 'Checking...' : 'VT Check'}
                        </motion.button>
                        {result.threat_type !== 'CLEAN' && (
                          <>
                            <motion.button
                              className="btn btn-primary btn-sm"
                              whileHover={{ scale: 1.05 }}
                              whileTap={{ scale: 0.95 }}
                              onClick={() => handleCleanFile(result.file_path)}
                              title="Attempt to remove virus signatures"
                            >
                              <Sparkles size={14} />
                              Clean
                            </motion.button>
                            <motion.button
                              className="btn btn-danger btn-sm"
                              whileHover={{ scale: 1.05 }}
                              whileTap={{ scale: 0.95 }}
                              onClick={() => toast.success('File quarantined')}
                            >
                              <Trash2 size={14} />
                              Quarantine
                            </motion.button>
                          </>
                        )}
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </motion.div>
          )}

          {/* Scan History */}
          {scanHistory.length > 0 && (
            <motion.div
              className="scan-history-section"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
            >
              <div className="history-header">
                <h3>Recent Scans</h3>
                <motion.button
                  className="btn btn-secondary btn-sm"
                  onClick={() => setScanHistory([])}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <RefreshCw size={14} />
                  Clear History
                </motion.button>
              </div>
              <div className="history-list">
                {scanHistory.map((scan) => (
                  <motion.div
                    key={scan.id}
                    className="history-item"
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    whileHover={{ x: 4 }}
                  >
                    <div className="history-icon">
                      {scan.type === 'file' ? <File size={16} /> : <FolderOpen size={16} />}
                    </div>
                    <div className="history-content">
                      <h5>{scan.path}</h5>
                      <div className="history-meta">
                        <span className="scan-time">
                          <Clock size={12} />
                          {scan.timestamp}
                        </span>
                        <span className="scan-duration">{scan.duration}s</span>
                      </div>
                    </div>
                    <div className="history-stats">
                      <span className="files-count">{scan.results} files</span>
                      {scan.threats > 0 && (
                        <span className="threats-count">{scan.threats} threats</span>
                      )}
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          )}
        </div>
      </div>
    </motion.div>
  );
});

Scanner.displayName = 'Scanner';

export default Scanner;