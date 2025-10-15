import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  File,
  X
} from 'lucide-react';
import AntivirusAPI from '../services/antivirusApi';
import './ProtectionMonitor.css';

const ProtectionMonitor = ({ isActive }) => {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({
    filesMonitored: 0,
    blockedThreats: 0,
    activeScans: 0
  });

  useEffect(() => {
    if (!isActive) {
      setEvents([]);
      setStats({ filesMonitored: 0, blockedThreats: 0, activeScans: 0 });
      return;
    }

    loadProtectionEvents();
    const interval = setInterval(loadProtectionEvents, 5000); // Update every 5 seconds
    return () => clearInterval(interval);
  }, [isActive]);

  const loadProtectionEvents = async () => {
    try {
      // Try to get status, fallback to basic data if endpoints don't exist
      const statusData = await AntivirusAPI.getProtectionStatus().catch(() => ({
        filesMonitored: 0,
        blockedThreats: 0,
        activeScans: 0
      }));
      
      const eventsData = await AntivirusAPI.getProtectionEvents().catch(() => ({
        events: []
      }));

      setStats({
        filesMonitored: statusData.filesMonitored || 0,
        blockedThreats: statusData.blockedThreats || 0,
        activeScans: statusData.activeScans || 0
      });

      if (eventsData.events && eventsData.events.length > 0) {
        setEvents(prev => {
          const newEvents = [...eventsData.events, ...prev].slice(0, 10);
          return newEvents;
        });
      }
    } catch (error) {
      // Silently fail - protection monitor will show basic status
      console.log('Protection events not available (endpoint not implemented)');
    }
  };

  const getEventIcon = (type) => {
    switch (type) {
      case 'threat_blocked':
        return <AlertTriangle size={16} className="event-icon danger" />;
      case 'file_cleaned':
        return <CheckCircle size={16} className="event-icon success" />;
      default:
        return <File size={16} className="event-icon info" />;
    }
  };

  const getEventLabel = (type) => {
    switch (type) {
      case 'threat_blocked':
        return 'Threat Blocked';
      case 'file_cleaned':
        return 'File Cleaned';
      case 'file_scanned':
        return 'File Scanned';
      default:
        return 'Activity';
    }
  };

  const removeEvent = (id) => {
    setEvents(prev => prev.filter(e => e.id !== id));
  };

  if (!isActive) {
    return (
      <motion.div
        className="protection-monitor inactive"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="monitor-header">
          <Shield size={20} className="inactive-icon" />
          <h3>Real-time Protection Disabled</h3>
        </div>
        <p className="monitor-message">
          Enable real-time protection in Settings to monitor file system activity
        </p>
      </motion.div>
    );
  }

  return (
    <motion.div
      className="protection-monitor active"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <div className="monitor-header">
        <div className="header-left">
          <Shield size={20} className="active-icon" />
          <h3>Real-time Protection</h3>
          <span className="status-badge active">
            <Activity size={12} />
            Monitoring
          </span>
        </div>
      </div>

      <div className="monitor-stats">
        <div className="stat-item">
          <File size={16} />
          <div>
            <span className="stat-value">{stats.filesMonitored.toLocaleString()}</span>
            <span className="stat-label">Files Monitored</span>
          </div>
        </div>
        <div className="stat-item">
          <AlertTriangle size={16} />
          <div>
            <span className="stat-value">{stats.blockedThreats}</span>
            <span className="stat-label">Threats Blocked</span>
          </div>
        </div>
        <div className="stat-item">
          <Activity size={16} />
          <div>
            <span className="stat-value">{stats.activeScans}</span>
            <span className="stat-label">Active Scans</span>
          </div>
        </div>
      </div>

      <div className="events-section">
        <h4>Recent Activity</h4>
        <div className="events-list">
          <AnimatePresence>
            {events.length > 0 ? (
              events.map((event) => (
                <motion.div
                  key={event.id}
                  className="event-item"
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  layout
                >
                  {getEventIcon(event.type)}
                  <div className="event-content">
                    <span className="event-label">{getEventLabel(event.type)}</span>
                    <span className="event-file">{event.filePath}</span>
                    <span className="event-time">
                      <Clock size={12} />
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <button 
                    className="event-dismiss"
                    onClick={() => removeEvent(event.id)}
                    title="Dismiss"
                  >
                    <X size={14} />
                  </button>
                </motion.div>
              ))
            ) : (
              <div className="no-events">
                <CheckCircle size={24} />
                <span>No recent activity</span>
              </div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  );
};

export default ProtectionMonitor;
