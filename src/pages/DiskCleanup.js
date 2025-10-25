import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  HardDrive,
  Trash2,
  FolderX,
  Download,
  Globe,
  FileText,
  RotateCcw,
  Sparkles,
  AlertCircle,
  CheckCircle,
  Loader,
  PieChart,
  TrendingUp,
  ZapOff
} from 'lucide-react';
import toast from 'react-hot-toast';
import './DiskCleanup.css';

// In development with React dev server, use proxy (relative URLs)
// In Electron or production, use direct backend URLs
const isElectron = typeof window !== 'undefined' && window.electronAPI?.isElectron;
const API_BASE_URL = isElectron ? 'http://localhost:8080' : '';

const DiskCleanup = () => {
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [cleaningStatus, setCleaningStatus] = useState({});
  const [totalCleaned, setTotalCleaned] = useState(0);

  useEffect(() => {
    analyzeDisks();
  }, []);

  const analyzeDisks = async () => {
    setAnalyzing(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/disk/analyze`);
      const data = await response.json();
      
      if (data.success) {
        setAnalysis(data);
        toast.success('Disk analysis complete!');
      } else {
        toast.error('Failed to analyze disk space');
      }
    } catch (error) {
      toast.error('Failed to connect to backend');
      console.error(error);
    } finally {
      setAnalyzing(false);
    }
  };

  const cleanCategory = async (category, endpoint, daysOld = null) => {
    setCleaningStatus(prev => ({ ...prev, [category]: 'cleaning' }));
    
    try {
      const body = daysOld ? JSON.stringify({ daysOld }) : undefined;
      const response = await fetch(`${API_BASE_URL}/api/disk/clean/${endpoint}`, {
        method: 'POST',
        headers: body ? { 'Content-Type': 'application/json' } : {},
        body
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      
      if (data.success) {
        setCleaningStatus(prev => ({ ...prev, [category]: 'success' }));
        setTotalCleaned(prev => prev + (data.cleaned || 0));
        
        if (data.cleaned === 0) {
          toast.success(
            `✅ ${data.location} is already clean!`,
            { duration: 3000 }
          );
        } else {
          toast.success(
            `✅ ${data.location} cleaned!\nFreed: ${formatBytes(data.cleaned || 0)}\nFiles: ${data.filesDeleted || 0}`,
            { duration: 5000 }
          );
        }
        
        // Re-analyze after cleaning
        setTimeout(analyzeDisks, 1000);
      } else {
        setCleaningStatus(prev => ({ ...prev, [category]: 'error' }));
        const errorMsg = data.error || 'Unknown error';
        toast.error(`Failed to clean ${data.location || category}: ${errorMsg}`, { duration: 5000 });
      }
    } catch (error) {
      setCleaningStatus(prev => ({ ...prev, [category]: 'error' }));
      toast.error(`Error cleaning ${category}: ${error.message}`, { duration: 5000 });
      console.error('Cleanup error:', error);
    }
  };

  const cleanAll = async () => {
    setLoading(true);
    toast.loading('Starting full disk cleanup...', { id: 'cleanup' });
    
    try {
      const response = await fetch(`${API_BASE_URL}/api/disk/clean/all`, {
        method: 'POST'
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      
      if (data.success) {
        setTotalCleaned(data.totalCleaned);
        
        if (data.totalCleaned === 0) {
          toast.success(
            '✅ All clean! No files to remove.',
            { id: 'cleanup', duration: 4000 }
          );
        } else {
          toast.success(
            `🎉 ${data.message}`,
            { id: 'cleanup', duration: 6000 }
          );
        }
        
        // Mark all as success
        setCleaningStatus({
          recyclebin: 'success',
          temp: 'success',
          downloads: 'success'
        });
        
        setTimeout(analyzeDisks, 1000);
      } else {
        const errorMsg = data.error || data.message || 'Unknown error';
        toast.error(`Cleanup failed: ${errorMsg}`, { id: 'cleanup', duration: 5000 });
      }
    } catch (error) {
      toast.error(`Failed to perform cleanup: ${error.message}`, { id: 'cleanup', duration: 5000 });
      console.error('Full cleanup error:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getStatusIcon = (category) => {
    const status = cleaningStatus[category];
    if (status === 'cleaning') return <Loader className="spin" size={20} />;
    if (status === 'success') return <CheckCircle size={20} />;
    if (status === 'error') return <AlertCircle size={20} />;
    return null;
  };

  const cleanupCategories = [
    {
      id: 'recyclebin',
      title: 'Recycle Bin',
      icon: Trash2,
      endpoint: 'recyclebin',
      color: '#ef4444',
      description: 'Empty your recycle bin',
      data: analysis?.analysis?.recycleBin
    },
    {
      id: 'temp',
      title: 'Temporary Files',
      icon: FolderX,
      endpoint: 'temp',
      color: '#f59e0b',
      description: 'Remove temporary system files',
      data: analysis?.analysis?.tempFiles
    },
    {
      id: 'downloads',
      title: 'Old Downloads',
      icon: Download,
      endpoint: 'downloads',
      color: '#3b82f6',
      description: 'Delete downloads older than 30 days',
      data: analysis?.analysis?.downloads,
      daysOld: 30
    },
    {
      id: 'browser',
      title: 'Browser Cache',
      icon: Globe,
      endpoint: 'browser',
      color: '#8b5cf6',
      description: 'Clear browser cache files',
      data: analysis?.analysis?.browserCache,
      comingSoon: true
    },
    {
      id: 'logs',
      title: 'System Logs',
      icon: FileText,
      endpoint: 'logs',
      color: '#06b6d4',
      description: 'Remove old system log files',
      data: analysis?.analysis?.logs,
      comingSoon: true
    }
  ];

  return (
    <div className="disk-cleanup-page">
      <div className="page-header">
        <div className="header-content">
          <div className="header-icon">
            <HardDrive size={32} />
          </div>
          <div>
            <h1>Disk Cleanup & Optimization</h1>
            <p>Free up disk space by removing unnecessary files</p>
          </div>
        </div>
        <button 
          className="btn btn-primary btn-lg"
          onClick={cleanAll}
          disabled={loading || analyzing}
        >
          {loading ? (
            <>
              <Loader className="spin" size={20} />
              Cleaning...
            </>
          ) : (
            <>
              <Sparkles size={20} />
              Clean All
            </>
          )}
        </button>
      </div>

      {/* Summary Cards */}
      <div className="summary-grid">
        <motion.div 
          className="summary-card total"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="card-icon">
            <HardDrive size={28} />
          </div>
          <div className="card-content">
            <h3>Total Cleanable</h3>
            <p className="card-value">
              {analyzing ? (
                <Loader className="spin" size={24} />
              ) : (
                formatBytes(analysis?.totalCleanable || 0)
              )}
            </p>
          </div>
        </motion.div>

        <motion.div 
          className="summary-card files"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <div className="card-icon">
            <FileText size={28} />
          </div>
          <div className="card-content">
            <h3>Files to Remove</h3>
            <p className="card-value">
              {analyzing ? (
                <Loader className="spin" size={24} />
              ) : (
                (analysis?.totalFiles || 0).toLocaleString()
              )}
            </p>
          </div>
        </motion.div>

        <motion.div 
          className="summary-card cleaned"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="card-icon">
            <TrendingUp size={28} />
          </div>
          <div className="card-content">
            <h3>Space Freed</h3>
            <p className="card-value success">
              {formatBytes(totalCleaned)}
            </p>
          </div>
        </motion.div>
      </div>

      {/* Cleanup Categories */}
      <div className="cleanup-categories">
        <div className="section-header">
          <h2>
            <PieChart size={24} />
            Cleanup Categories
          </h2>
          <button 
            className="btn btn-secondary"
            onClick={analyzeDisks}
            disabled={analyzing}
          >
            {analyzing ? (
              <>
                <Loader className="spin" size={18} />
                Analyzing...
              </>
            ) : (
              <>
                <RotateCcw size={18} />
                Re-analyze
              </>
            )}
          </button>
        </div>

        <div className="categories-grid">
          {cleanupCategories.map((category, index) => (
            <motion.div
              key={category.id}
              className={`category-card ${cleaningStatus[category.id] || ''} ${category.comingSoon ? 'coming-soon' : ''}`}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: index * 0.1 }}
            >
              <div className="category-header">
                <div 
                  className="category-icon"
                  style={{ background: `${category.color}22`, color: category.color }}
                >
                  <category.icon size={32} />
                </div>
                <div className="category-info">
                  <h3>{category.title}</h3>
                  <p>{category.description}</p>
                </div>
              </div>

              <div className="category-stats">
                <div className="stat">
                  <span className="stat-label">Size</span>
                  <span className="stat-value">
                    {analyzing ? (
                      <Loader className="spin" size={16} />
                    ) : (
                      formatBytes(category.data?.size || 0)
                    )}
                  </span>
                </div>
                <div className="stat">
                  <span className="stat-label">Files</span>
                  <span className="stat-value">
                    {analyzing ? (
                      <Loader className="spin" size={16} />
                    ) : (
                      (category.data?.count || 0).toLocaleString()
                    )}
                  </span>
                </div>
              </div>

              {category.comingSoon ? (
                <button className="btn btn-secondary btn-block" disabled>
                  <ZapOff size={18} />
                  Coming Soon
                </button>
              ) : (
                <button
                  className="btn btn-primary btn-block"
                  onClick={() => cleanCategory(category.id, category.endpoint, category.daysOld)}
                  disabled={
                    analyzing || 
                    cleaningStatus[category.id] === 'cleaning' ||
                    !category.data?.size
                  }
                  style={{ borderColor: category.color }}
                >
                  {cleaningStatus[category.id] === 'cleaning' ? (
                    <>
                      <Loader className="spin" size={18} />
                      Cleaning...
                    </>
                  ) : cleaningStatus[category.id] === 'success' ? (
                    <>
                      <CheckCircle size={18} />
                      Cleaned
                    </>
                  ) : (
                    <>
                      <Trash2 size={18} />
                      Clean Now
                    </>
                  )}
                </button>
              )}
            </motion.div>
          ))}
        </div>
      </div>

      {/* Recommendations */}
      {analysis?.recommendations && analysis.recommendations.length > 0 && (
        <div className="recommendations">
          <h2>
            <AlertCircle size={24} />
            Recommendations
          </h2>
          <div className="recommendations-list">
            {analysis.recommendations.map((rec, index) => (
              <motion.div
                key={index}
                className={`recommendation-card priority-${rec.priority}`}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <div className="rec-priority">{rec.priority.toUpperCase()}</div>
                <div className="rec-content">
                  <h4>{rec.action}</h4>
                  <p>{rec.description}</p>
                </div>
                <div className="rec-savings">
                  {formatBytes(rec.savings)}
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default DiskCleanup;
