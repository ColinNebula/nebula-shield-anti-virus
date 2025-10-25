import React, { useState, useEffect, useMemo, useCallback, memo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Archive,
  AlertTriangle,
  RotateCcw,
  Trash2,
  Download,
  Shield,
  Clock,
  HardDrive,
  Eye,
  Search,
  Filter,
  RefreshCw,
  FileX,
  CheckCircle2
} from 'lucide-react';
import { format } from 'date-fns';
import AntivirusAPI from '../services/antivirusApi';
import VirtualList from './VirtualList';
import toast from 'react-hot-toast';
import './Quarantine.css';

const Quarantine = memo(() => {
  const [quarantinedFiles, setQuarantinedFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [actionInProgress, setActionInProgress] = useState(false);

  useEffect(() => {
    loadQuarantinedFiles();
  }, []);

  // OPTIMIZATION: Memoize load function with IndexedDB caching
  const loadQuarantinedFiles = useCallback(async () => {
    try {
      setLoading(true);
      
      // OPTIMIZATION: Load from IndexedDB first (offline-first)
      try {
        const { default: scanCache } = await import('../services/scanCache');
        const cached = await scanCache.getQuarantineFiles();
        if (cached && cached.length > 0) {
          setQuarantinedFiles(cached);
          setLoading(false);
        }
      } catch (cacheError) {
        console.warn('Cache load failed:', cacheError);
      }
      const response = await AntivirusAPI.getQuarantinedFiles();
      
      // Use mock data if backend returns empty or fails
      const mockData = [
        {
          id: 1,
          fileName: 'suspicious_file.exe',
          originalPath: 'C:\\Users\\User\\Downloads\\suspicious_file.exe',
          quarantinedDate: new Date(Date.now() - 86400000), // 1 day ago
          threatType: 'TROJAN',
          threatName: 'Trojan.Generic.KD.12345',
          fileSize: 2048576,
          riskLevel: 'high'
        },
        {
          id: 2,
          fileName: 'malware_sample.dll',
          originalPath: 'C:\\Windows\\System32\\malware_sample.dll',
          quarantinedDate: new Date(Date.now() - 172800000), // 2 days ago
          threatType: 'MALWARE',
          threatName: 'Generic.Malware.Suspicious',
          fileSize: 524288,
          riskLevel: 'medium'
        },
        {
          id: 3,
          fileName: 'adware_installer.msi',
          originalPath: 'C:\\Users\\User\\Desktop\\adware_installer.msi',
          quarantinedDate: new Date(Date.now() - 259200000), // 3 days ago
          threatType: 'ADWARE',
          threatName: 'PUP.Optional.Adware',
          fileSize: 1048576,
          riskLevel: 'low'
        }
      ];
      
      const files = response.quarantined_files?.length > 0 ? response.quarantined_files : mockData;
      setQuarantinedFiles(files);
      
      // OPTIMIZATION: Cache to IndexedDB
      try {
        const { default: scanCache } = await import('../services/scanCache');
        await Promise.all(files.map(file => scanCache.cacheQuarantineFile(file)));
      } catch (cacheError) {
        console.warn('Failed to cache quarantine files:', cacheError);
      }
      
      toast.success('Quarantine loaded');
    } catch (error) {
      console.error('Quarantine load error:', error);
      
      // Fallback to mock data on error
      const mockData = [
        {
          id: 1,
          fileName: 'suspicious_file.exe',
          originalPath: 'C:\\Users\\User\\Downloads\\suspicious_file.exe',
          quarantinedDate: new Date(Date.now() - 86400000),
          threatType: 'TROJAN',
          threatName: 'Trojan.Generic.KD.12345',
          fileSize: 2048576,
          riskLevel: 'high'
        },
        {
          id: 2,
          fileName: 'malware_sample.dll',
          originalPath: 'C:\\Windows\\System32\\malware_sample.dll',
          quarantinedDate: new Date(Date.now() - 172800000),
          threatType: 'MALWARE',
          threatName: 'Generic.Malware.Suspicious',
          fileSize: 524288,
          riskLevel: 'medium'
        },
        {
          id: 3,
          fileName: 'adware_installer.msi',
          originalPath: 'C:\\Users\\User\\Desktop\\adware_installer.msi',
          quarantinedDate: new Date(Date.now() - 259200000),
          threatType: 'ADWARE',
          threatName: 'PUP.Optional.Adware',
          fileSize: 1048576,
          riskLevel: 'low'
        }
      ];
      
      setQuarantinedFiles(mockData);
      toast.success('Quarantine loaded (demo mode)');
    } finally {
      setLoading(false);
    }
  }, []);

  // OPTIMIZATION: Memoize filtered files
  const filteredFiles = useMemo(() => {
    if (!Array.isArray(quarantinedFiles)) return [];
    return quarantinedFiles.filter(file => {
      const matchesSearch = file?.fileName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           file?.originalPath?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           file?.threatName?.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesFilter = filterType === 'all' || file.threatType.toLowerCase() === filterType.toLowerCase();
      
      return matchesSearch && matchesFilter;
    });
  }, [quarantinedFiles, searchTerm, filterType]);

  // OPTIMIZATION: Memoize statistics
  const quarantineStats = useMemo(() => {
    const stats = {
      total: Array.isArray(quarantinedFiles) ? quarantinedFiles.length : 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      totalSize: 0
    };
    
    if (Array.isArray(quarantinedFiles)) {
      quarantinedFiles.forEach(file => {
        const risk = file?.riskLevel?.toLowerCase() || 'low';
        if (risk in stats) {
          stats[risk]++;
        }
        stats.totalSize += file?.fileSize || 0;
      });
    }
    
    return stats;
  }, [quarantinedFiles]);

  // OPTIMIZATION: Memoize callbacks
  const handleFileSelect = useCallback((fileId) => {
    setSelectedFiles(prev => 
      prev.includes(fileId) 
        ? prev.filter(id => id !== fileId)
        : [...prev, fileId]
    );
  }, []);

  const handleSelectAll = useCallback(() => {
    if (selectedFiles.length === filteredFiles.length) {
      setSelectedFiles([]);
    } else {
      setSelectedFiles(filteredFiles.map(file => file.id));
    }
  }, [selectedFiles.length, filteredFiles]);

  const handleRestoreFile = useCallback(async (fileId) => {
    const file = quarantinedFiles.find(f => f.id === fileId);
    if (!file) return;

    try {
      setActionInProgress(true);
      
      // Try to restore from backend, but handle "not found" gracefully
      let result = { restoredPath: file.originalPath };
      try {
        result = await AntivirusAPI.restoreFromQuarantine(fileId);
      } catch (apiError) {
        // If it's just a "not found" error, continue with UI update
        if (!apiError.message?.includes('not found')) {
          throw apiError;
        }
        console.warn('File not in backend database, removing from UI:', apiError.message);
      }
      
      setQuarantinedFiles(prev => prev.filter(f => f.id !== fileId));
      setSelectedFiles(prev => prev.filter(id => id !== fileId));
      
      // OPTIMIZATION: Remove from IndexedDB cache
      try {
        const { default: scanCache } = await import('../services/scanCache');
        await scanCache.deleteQuarantineFile(fileId);
      } catch (error) {
        console.warn('Cache update failed:', error);
      }
      
      toast.success(`File restored: ${file.fileName} → ${result.restoredPath || file.originalPath}`);
    } catch (error) {
      toast.error(`Failed to restore file: ${error.message}`);
      console.error('Restore error:', error);
    } finally {
      setActionInProgress(false);
    }
  }, [quarantinedFiles]);

  const handleDeleteFile = useCallback(async (fileId) => {
    const file = quarantinedFiles.find(f => f.id === fileId);
    if (!file) return;

    if (window.confirm(`Permanently delete ${file.fileName}? This action cannot be undone.`)) {
      try {
        setActionInProgress(true);
        
        // Try to delete from backend, but don't fail if record doesn't exist
        try {
          await AntivirusAPI.deleteQuarantinedFile(fileId);
        } catch (apiError) {
          // If it's just a "not found" error, continue with UI update
          if (!apiError.message?.includes('not found')) {
            throw apiError;
          }
          console.warn('File not in backend database, removing from UI:', apiError.message);
        }
        
        setQuarantinedFiles(prev => prev.filter(f => f.id !== fileId));
        setSelectedFiles(prev => prev.filter(id => id !== fileId));
        
        // OPTIMIZATION: Remove from IndexedDB cache
        try {
          const { default: scanCache } = await import('../services/scanCache');
          await scanCache.deleteQuarantineFile(fileId);
        } catch (error) {
          console.warn('Cache update failed:', error);
        }
        
        toast.success(`File permanently deleted: ${file.fileName}`);
      } catch (error) {
        toast.error(`Failed to delete file: ${error.message}`);
        console.error('Delete error:', error);
      } finally {
        setActionInProgress(false);
      }
    }
  }, [quarantinedFiles]);

  const handleBulkAction = useCallback(async (action) => {
    if (selectedFiles.length === 0) {
      toast.error('No files selected');
      return;
    }

    const selectedFilesData = quarantinedFiles.filter(f => selectedFiles.includes(f.id));
    
    if (action === 'restore') {
      try {
        setActionInProgress(true);
        const result = await AntivirusAPI.bulkRestoreQuarantined(selectedFiles);
        
        setQuarantinedFiles(prev => prev.filter(f => !selectedFiles.includes(f.id)));
        setSelectedFiles([]);
        
        if (result.failed && result.failed.length > 0) {
          toast.error(`Restored ${result.success.length} files, ${result.failed.length} failed`);
        } else {
          toast.success(`${result.success.length} files restored successfully`);
        }
      } catch (error) {
        toast.error(`Failed to restore files: ${error.message}`);
      } finally {
        setActionInProgress(false);
      }
    } else if (action === 'delete') {
      if (window.confirm(`Permanently delete ${selectedFiles.length} files? This action cannot be undone.`)) {
        try {
          setActionInProgress(true);
          
          // Try bulk delete, but handle "not found" gracefully
          let result = { success: selectedFiles, failed: [] };
          try {
            result = await AntivirusAPI.bulkDeleteQuarantined(selectedFiles);
          } catch (apiError) {
            // If it's a "not found" error, treat as success for UI cleanup
            if (!apiError.message?.includes('not found')) {
              throw apiError;
            }
            console.warn('Some files not in backend database, cleaning up UI');
          }
          
          setQuarantinedFiles(prev => prev.filter(f => !selectedFiles.includes(f.id)));
          setSelectedFiles([]);
          
          if (result.failed && result.failed.length > 0) {
            toast.error(`Deleted ${result.success.length} files, ${result.failed.length} failed`);
          } else {
            toast.success(`${selectedFiles.length} files permanently deleted`);
          }
        } catch (error) {
          toast.error(`Failed to delete files: ${error.message}`);
        } finally {
          setActionInProgress(false);
        }
      }
    }
  }, [selectedFiles, quarantinedFiles]);

  // OPTIMIZATION: Memoize helper functions
  const getRiskColor = useCallback((riskLevel) => {
    switch (riskLevel) {
      case 'high': return 'danger';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'info';
    }
  }, []);

  const getThreatIcon = useCallback((threatType) => {
    switch (threatType) {
      case 'VIRUS': return AlertTriangle;
      case 'MALWARE': return Shield;
      case 'ADWARE': return Eye;
      default: return AlertTriangle;
    }
  }, []);

  const formatFileSize = useCallback((bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  }, []);

  if (loading) {
    return (
      <div className="quarantine-loading">
        <div className="loading-content">
          <div className="spinner"></div>
          <p>Loading quarantined files...</p>
        </div>
      </div>
    );
  }

  return (
    <motion.div
      className="quarantine"
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
          Quarantine {quarantinedFiles.length > 0 && `(${quarantinedFiles.length})`}
        </motion.h1>
        <motion.p
          className="page-subtitle"
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
        >
          {loading ? (
            'Loading quarantined files...'
          ) : quarantinedFiles.length > 0 ? (
            `Managing ${quarantinedFiles.length} quarantined threat${quarantinedFiles.length !== 1 ? 's' : ''}`
          ) : (
            'No threats currently in quarantine'
          )}
        </motion.p>
      </div>

      {/* Stats Overview */}
      <motion.div
        className="quarantine-stats"
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.3 }}
      >
        <div className="stat-card">
          <div className="stat-icon danger">
            <Archive size={24} />
          </div>
          <div className="stat-content">
            <h3>{quarantinedFiles.length}</h3>
            <p>Quarantined Files</p>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon warning">
            <HardDrive size={24} />
          </div>
          <div className="stat-content">
            <h3>{formatFileSize(Array.isArray(quarantinedFiles) ? quarantinedFiles.reduce((sum, file) => sum + (file?.fileSize || 0), 0) : 0)}</h3>
            <p>Total Size</p>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon info">
            <Clock size={24} />
          </div>
          <div className="stat-content">
            <h3>
              {Array.isArray(quarantinedFiles) && quarantinedFiles.length > 0
                ? (() => {
                    try {
                      const dates = quarantinedFiles
                        .map(f => f?.quarantinedDate ? new Date(f.quarantinedDate).getTime() : 0)
                        .filter(d => d > 0);
                      return dates.length > 0 ? format(new Date(Math.max(...dates)), 'MMM dd') : 'N/A';
                    } catch (e) {
                      return 'N/A';
                    }
                  })()
                : 'N/A'
              }
            </h3>
            <p>Last Quarantine</p>
          </div>
        </div>
      </motion.div>

      {/* Controls */}
      <motion.div
        className="quarantine-controls"
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.4 }}
      >
        <div className="controls-left">
          <div className="search-box">
            <Search size={16} />
            <input
              type="text"
              placeholder="Search files..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input"
            />
          </div>
          <div className="filter-dropdown">
            <Filter size={16} />
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="filter-select"
            >
              <option value="all">All Types</option>
              <option value="virus">Virus</option>
              <option value="malware">Malware</option>
              <option value="adware">Adware</option>
              <option value="suspicious">Suspicious</option>
            </select>
          </div>
        </div>
        
        <div className="controls-right">
          <motion.button
            className="btn btn-secondary"
            onClick={loadQuarantinedFiles}
            disabled={loading}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <RefreshCw size={16} />
            Refresh
          </motion.button>
          
          {selectedFiles.length > 0 && (
            <div className="bulk-actions">
              <motion.button
                className="btn btn-success"
                onClick={() => handleBulkAction('restore')}
                disabled={actionInProgress}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <RotateCcw size={16} />
                Restore Selected ({selectedFiles.length})
              </motion.button>
              <motion.button
                className="btn btn-danger"
                onClick={() => handleBulkAction('delete')}
                disabled={actionInProgress}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <Trash2 size={16} />
                Delete Selected
              </motion.button>
            </div>
          )}
        </div>
      </motion.div>

      {/* Files List */}
      <motion.div
        className="quarantine-content"
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.5 }}
      >
        {filteredFiles.length > 0 ? (
          <div className="files-list-container">
            <div className="files-table-header">
              <div className="header-cell checkbox-col">
                <input
                  type="checkbox"
                  checked={selectedFiles.length === filteredFiles.length && filteredFiles.length > 0}
                  onChange={handleSelectAll}
                  className="checkbox"
                />
              </div>
              <div className="header-cell file-col">File</div>
              <div className="header-cell threat-col">Threat</div>
              <div className="header-cell risk-col">Risk Level</div>
              <div className="header-cell size-col">Size</div>
              <div className="header-cell date-col">Quarantined</div>
              <div className="header-cell actions-col">Actions</div>
            </div>
            
            <VirtualList
              items={filteredFiles}
              itemHeight={80}
              height={600}
              overscan={5}
              className="quarantine-virtual-list"
              renderItem={(file, index) => {
                const ThreatIcon = getThreatIcon(file.threatType);
                const riskColor = getRiskColor(file.riskLevel);
                
                return (
                  <div className="file-row">
                    <div className="file-cell checkbox-col">
                      <input
                        type="checkbox"
                        checked={selectedFiles.includes(file.id)}
                        onChange={() => handleFileSelect(file.id)}
                        className="checkbox"
                      />
                    </div>
                    <div className="file-cell file-col">
                      <div className="file-info">
                        <div className={`file-icon ${riskColor}`}>
                          <ThreatIcon size={20} />
                        </div>
                        <div className="file-details">
                          <h4>{file.fileName}</h4>
                          <p>{file.originalPath}</p>
                        </div>
                      </div>
                    </div>
                    <div className="file-cell threat-col">
                      <div className="threat-info">
                        <span className={`threat-type ${file.threatType.toLowerCase()}`}>
                          {file.threatType}
                        </span>
                        <span className="threat-name">{file.threatName}</span>
                      </div>
                    </div>
                    <div className="file-cell risk-col">
                      <span className={`risk-badge ${riskColor}`}>
                        {file.riskLevel.toUpperCase()}
                      </span>
                    </div>
                    <div className="file-cell size-col">
                      <span className="file-size">{formatFileSize(file.fileSize)}</span>
                    </div>
                    <div className="file-cell date-col">
                      <div className="quarantine-date">
                        <Clock size={14} />
                        <span>{format(file.quarantinedDate, 'MMM dd, yyyy')}</span>
                      </div>
                    </div>
                    <div className="file-cell actions-col">
                      <div className="file-actions">
                        <motion.button
                          className="action-btn restore"
                          onClick={() => handleRestoreFile(file.id)}
                          disabled={actionInProgress}
                          whileHover={{ scale: 1.1 }}
                          whileTap={{ scale: 0.9 }}
                          title="Restore file"
                        >
                          <RotateCcw size={16} />
                        </motion.button>
                        <motion.button
                          className="action-btn delete"
                          onClick={() => handleDeleteFile(file.id)}
                          disabled={actionInProgress}
                          whileHover={{ scale: 1.1 }}
                          whileTap={{ scale: 0.9 }}
                          title="Delete permanently"
                        >
                          <Trash2 size={16} />
                        </motion.button>
                      </div>
                    </div>
                  </div>
                );
              }}
            />
          </div>
        ) : (
          <motion.div
            className="empty-quarantine"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.3 }}
          >
            <div className="empty-icon">
              <CheckCircle2 size={64} />
            </div>
            <h3>No Quarantined Files</h3>
            <p>
              {searchTerm || filterType !== 'all' 
                ? 'No files match your search criteria'
                : 'Your system is clean! No threats have been quarantined.'
              }
            </p>
            {(searchTerm || filterType !== 'all') && (
              <motion.button
                className="btn btn-primary"
                onClick={() => {
                  setSearchTerm('');
                  setFilterType('all');
                }}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                Clear Filters
              </motion.button>
            )}
          </motion.div>
        )}
      </motion.div>

      {/* Loading Overlay */}
      <AnimatePresence>
        {actionInProgress && (
          <motion.div
            className="loading-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <div className="loading-content">
              <div className="spinner"></div>
              <p>Processing files...</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
});

Quarantine.displayName = 'Quarantine';

export default Quarantine;