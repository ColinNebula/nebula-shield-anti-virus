import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import './AnimatedScanProgress.css';

/**
 * Animated Scan Progress - Visual feedback during scanning operations
 */
const AnimatedScanProgress = ({ 
  isScanning, 
  progress = 0, 
  currentFile = '', 
  scanType = 'quick',
  stats = { scanned: 0, threats: 0, cleaned: 0 },
  onCancel
}) => {
  const [particles, setParticles] = useState([]);
  const [scanWave, setScanWave] = useState(0);

  // Generate animated particles
  useEffect(() => {
    if (!isScanning) return;

    const interval = setInterval(() => {
      const newParticle = {
        id: Date.now() + Math.random(),
        x: Math.random() * 100,
        y: -10,
        size: Math.random() * 4 + 2,
        speed: Math.random() * 2 + 1,
        color: ['#4fc3f7', '#03a9f4', '#0288d1'][Math.floor(Math.random() * 3)]
      };

      setParticles(prev => [...prev.slice(-20), newParticle]);
    }, 100);

    return () => clearInterval(interval);
  }, [isScanning]);

  // Animate scan wave
  useEffect(() => {
    if (!isScanning) return;

    const interval = setInterval(() => {
      setScanWave(prev => (prev + 1) % 360);
    }, 50);

    return () => clearInterval(interval);
  }, [isScanning]);

  // Get scan type icon and label
  const getScanInfo = () => {
    switch (scanType) {
      case 'quick':
        return { icon: '⚡', label: 'Quick Scan', color: '#4fc3f7' };
      case 'full':
        return { icon: '🔍', label: 'Full System Scan', color: '#ff9800' };
      case 'custom':
        return { icon: '🎯', label: 'Custom Scan', color: '#9c27b0' };
      case 'memory':
        return { icon: '🧠', label: 'Memory Scan', color: '#e91e63' };
      default:
        return { icon: '🛡️', label: 'Scanning', color: '#4fc3f7' };
    }
  };

  const scanInfo = getScanInfo();

  // Format file path for display
  const formatFilePath = (path) => {
    if (!path) return 'Initializing...';
    if (path.length > 60) {
      return '...' + path.slice(-57);
    }
    return path;
  };

  if (!isScanning) return null;

  return (
    <div className="scan-progress-overlay">
      <motion.div
        className="scan-progress-container"
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.9 }}
        transition={{ type: "spring", stiffness: 300, damping: 25 }}
      >
        {/* Animated Background */}
        <div className="scan-background">
          <motion.div
            className="scan-wave"
            animate={{
              rotate: scanWave,
              scale: [1, 1.2, 1]
            }}
            transition={{
              rotate: { duration: 8, repeat: Infinity, ease: "linear" },
              scale: { duration: 2, repeat: Infinity, ease: "easeInOut" }
            }}
          />
          
          {/* Particles */}
          {particles.map(particle => (
            <motion.div
              key={particle.id}
              className="particle"
              initial={{ 
                x: particle.x + '%', 
                y: '-10px',
                opacity: 0 
              }}
              animate={{ 
                y: '110%',
                opacity: [0, 1, 0]
              }}
              transition={{ 
                duration: particle.speed,
                ease: "linear"
              }}
              style={{
                width: particle.size,
                height: particle.size,
                background: particle.color
              }}
              onAnimationComplete={() => {
                setParticles(prev => prev.filter(p => p.id !== particle.id));
              }}
            />
          ))}
        </div>

        {/* Scan Icon */}
        <motion.div
          className="scan-icon"
          animate={{
            scale: [1, 1.1, 1],
            rotate: [0, 360]
          }}
          transition={{
            scale: { duration: 2, repeat: Infinity, ease: "easeInOut" },
            rotate: { duration: 4, repeat: Infinity, ease: "linear" }
          }}
          style={{ color: scanInfo.color }}
        >
          <span>{scanInfo.icon}</span>
          
          {/* Orbiting elements */}
          <motion.div
            className="orbit-ring"
            animate={{ rotate: 360 }}
            transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
          >
            <div className="orbit-dot"></div>
          </motion.div>
          <motion.div
            className="orbit-ring"
            animate={{ rotate: -360 }}
            transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
          >
            <div className="orbit-dot"></div>
          </motion.div>
        </motion.div>

        {/* Scan Info */}
        <h3 className="scan-title">{scanInfo.label}</h3>
        
        {/* Progress Bar */}
        <div className="progress-section">
          <div className="progress-bar-container">
            <motion.div
              className="progress-bar-fill"
              initial={{ width: 0 }}
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.5, ease: "easeOut" }}
              style={{ background: `linear-gradient(90deg, ${scanInfo.color}, ${scanInfo.color}dd)` }}
            >
              {/* Shimmer effect */}
              <motion.div
                className="progress-shimmer"
                animate={{ x: ['-100%', '200%'] }}
                transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
              />
            </motion.div>
          </div>
          <div className="progress-percentage">
            <motion.span
              key={progress}
              initial={{ scale: 1.2 }}
              animate={{ scale: 1 }}
              transition={{ type: "spring", stiffness: 500 }}
            >
              {Math.round(progress)}%
            </motion.span>
          </div>
        </div>

        {/* Current File */}
        <motion.div 
          className="current-file"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          key={currentFile}
        >
          <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" className="file-icon">
            <path d="M9 1H3a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2V7l-6-6z"/>
            <path d="M9 1v6h6"/>
          </svg>
          <span>{formatFilePath(currentFile)}</span>
        </motion.div>

        {/* Stats Grid */}
        <div className="scan-stats">
          <motion.div 
            className="stat-item"
            whileHover={{ scale: 1.05 }}
          >
            <div className="stat-icon scanned">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path d="M4 2h12a2 2 0 012 2v12a2 2 0 01-2 2H4a2 2 0 01-2-2V4a2 2 0 012-2zm1 2v12h10V4H5z"/>
                <path d="M7 6h6v2H7zm0 4h6v2H7z"/>
              </svg>
            </div>
            <div className="stat-content">
              <div className="stat-value">
                <motion.span
                  key={stats.scanned}
                  initial={{ scale: 1.3 }}
                  animate={{ scale: 1 }}
                >
                  {stats.scanned.toLocaleString()}
                </motion.span>
              </div>
              <div className="stat-label">Files Scanned</div>
            </div>
          </motion.div>

          <motion.div 
            className="stat-item"
            whileHover={{ scale: 1.05 }}
          >
            <div className="stat-icon threats">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path d="M10 2l-8 4v5c0 5 3.5 9.5 8 10.5 4.5-1 8-5.5 8-10.5V6l-8-4z"/>
                <path d="M9 8h2v4H9zm0 6h2v2H9z" fill="#fff"/>
              </svg>
            </div>
            <div className="stat-content">
              <div className="stat-value threats-value">
                <motion.span
                  key={stats.threats}
                  initial={{ scale: 1.3 }}
                  animate={{ scale: 1 }}
                >
                  {stats.threats.toLocaleString()}
                </motion.span>
              </div>
              <div className="stat-label">Threats Found</div>
            </div>
          </motion.div>

          <motion.div 
            className="stat-item"
            whileHover={{ scale: 1.05 }}
          >
            <div className="stat-icon cleaned">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                <path d="M10 2a8 8 0 100 16 8 8 0 000-16zM8 13L4 9l1.5-1.5L8 10l6.5-6.5L16 5l-8 8z"/>
              </svg>
            </div>
            <div className="stat-content">
              <div className="stat-value cleaned-value">
                <motion.span
                  key={stats.cleaned}
                  initial={{ scale: 1.3 }}
                  animate={{ scale: 1 }}
                >
                  {stats.cleaned.toLocaleString()}
                </motion.span>
              </div>
              <div className="stat-label">Cleaned</div>
            </div>
          </motion.div>
        </div>

        {/* Action Buttons */}
        <div className="scan-actions">
          <motion.button
            className="scan-cancel-btn"
            onClick={onCancel}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 12.5A5.5 5.5 0 1113.5 8 5.51 5.51 0 018 13.5z"/>
              <path d="M10.5 5.5L8 8l-2.5-2.5L4 7l2.5 2.5L4 12l1.5 1.5L8 11l2.5 2.5L12 12 9.5 9.5 12 7z"/>
            </svg>
            <span>Cancel Scan</span>
          </motion.button>
        </div>

        {/* Pulse effect around container */}
        <motion.div
          className="scan-pulse"
          animate={{
            scale: [1, 1.1, 1],
            opacity: [0.3, 0.1, 0.3]
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: "easeInOut"
          }}
        />
      </motion.div>
    </div>
  );
};

export default AnimatedScanProgress;
