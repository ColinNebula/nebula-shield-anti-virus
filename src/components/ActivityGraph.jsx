import React, { useEffect, useRef, useState } from 'react';
import { Line } from 'react-chartjs-2';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import './ActivityGraph.css';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

/**
 * Real-time Activity Graph - Live visualization of system protection events
 */
const ActivityGraph = ({ maxDataPoints = 30, updateInterval = 1000 }) => {
  const [activityData, setActivityData] = useState({
    scans: [],
    threats: [],
    blocked: [],
    timestamps: []
  });
  const [stats, setStats] = useState({
    totalScans: 0,
    totalThreats: 0,
    totalBlocked: 0,
    avgResponseTime: 0
  });
  const [activeEvents, setActiveEvents] = useState([]);
  const intervalRef = useRef(null);

  // Simulate real-time data (replace with actual data from your backend)
  useEffect(() => {
    const generateDataPoint = () => {
      const now = new Date();
      const timeStr = now.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit' 
      });

      // Simulate activity (replace with real data)
      const scans = Math.floor(Math.random() * 10);
      const threats = Math.floor(Math.random() * 3);
      const blocked = threats > 0 ? Math.floor(Math.random() * threats) : 0;

      setActivityData(prev => {
        const newData = {
          scans: [...prev.scans, scans].slice(-maxDataPoints),
          threats: [...prev.threats, threats].slice(-maxDataPoints),
          blocked: [...prev.blocked, blocked].slice(-maxDataPoints),
          timestamps: [...prev.timestamps, timeStr].slice(-maxDataPoints)
        };
        return newData;
      });

      // Update stats
      setStats(prev => ({
        totalScans: prev.totalScans + scans,
        totalThreats: prev.totalThreats + threats,
        totalBlocked: prev.totalBlocked + blocked,
        avgResponseTime: Math.floor(Math.random() * 100 + 50) // ms
      }));

      // Add event notifications
      if (threats > 0) {
        const event = {
          id: Date.now(),
          type: blocked > 0 ? 'blocked' : 'detected',
          count: threats,
          timestamp: now
        };
        setActiveEvents(prev => [...prev, event].slice(-5));
        
        // Remove event after 5 seconds
        setTimeout(() => {
          setActiveEvents(prev => prev.filter(e => e.id !== event.id));
        }, 5000);
      }
    };

    // Initial data
    for (let i = 0; i < maxDataPoints; i++) {
      generateDataPoint();
    }

    // Set up interval
    intervalRef.current = setInterval(generateDataPoint, updateInterval);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [maxDataPoints, updateInterval]);

  const chartData = {
    labels: activityData.timestamps,
    datasets: [
      {
        label: 'Scans',
        data: activityData.scans,
        borderColor: 'rgba(79, 195, 247, 1)',
        backgroundColor: 'rgba(79, 195, 247, 0.1)',
        borderWidth: 2,
        tension: 0.4,
        fill: true,
        pointRadius: 0,
        pointHoverRadius: 6,
        pointHoverBackgroundColor: 'rgba(79, 195, 247, 1)',
        pointHoverBorderColor: '#fff',
        pointHoverBorderWidth: 2
      },
      {
        label: 'Threats Detected',
        data: activityData.threats,
        borderColor: 'rgba(255, 152, 0, 1)',
        backgroundColor: 'rgba(255, 152, 0, 0.1)',
        borderWidth: 2,
        tension: 0.4,
        fill: true,
        pointRadius: 0,
        pointHoverRadius: 6,
        pointHoverBackgroundColor: 'rgba(255, 152, 0, 1)',
        pointHoverBorderColor: '#fff',
        pointHoverBorderWidth: 2
      },
      {
        label: 'Blocked',
        data: activityData.blocked,
        borderColor: 'rgba(76, 175, 80, 1)',
        backgroundColor: 'rgba(76, 175, 80, 0.1)',
        borderWidth: 2,
        tension: 0.4,
        fill: true,
        pointRadius: 0,
        pointHoverRadius: 6,
        pointHoverBackgroundColor: 'rgba(76, 175, 80, 1)',
        pointHoverBorderColor: '#fff',
        pointHoverBorderWidth: 2
      }
    ]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
      duration: 750,
      easing: 'easeInOutQuart'
    },
    plugins: {
      legend: {
        display: true,
        position: 'top',
        labels: {
          color: 'rgba(255, 255, 255, 0.8)',
          font: {
            size: 12,
            weight: '500'
          },
          usePointStyle: true,
          padding: 15
        }
      },
      tooltip: {
        mode: 'index',
        intersect: false,
        backgroundColor: 'rgba(26, 26, 46, 0.95)',
        titleColor: '#4fc3f7',
        bodyColor: 'rgba(255, 255, 255, 0.9)',
        borderColor: '#4fc3f7',
        borderWidth: 1,
        padding: 12,
        displayColors: true,
        callbacks: {
          title: (context) => {
            return `Time: ${context[0].label}`;
          }
        }
      }
    },
    scales: {
      x: {
        display: true,
        grid: {
          color: 'rgba(79, 195, 247, 0.1)',
          drawBorder: false
        },
        ticks: {
          color: 'rgba(255, 255, 255, 0.6)',
          maxRotation: 0,
          autoSkip: true,
          maxTicksLimit: 8,
          font: {
            size: 10
          }
        }
      },
      y: {
        display: true,
        beginAtZero: true,
        grid: {
          color: 'rgba(79, 195, 247, 0.1)',
          drawBorder: false
        },
        ticks: {
          color: 'rgba(255, 255, 255, 0.6)',
          stepSize: 1,
          font: {
            size: 10
          }
        }
      }
    },
    interaction: {
      mode: 'nearest',
      axis: 'x',
      intersect: false
    }
  };

  return (
    <div className="activity-graph-container">
      <div className="activity-graph-header">
        <h3>
          <span className="pulse-dot"></span>
          Real-Time Activity Monitor
        </h3>
        <div className="graph-controls">
          <button className="control-btn" title="Pause">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
              <rect x="4" y="3" width="3" height="10" />
              <rect x="9" y="3" width="3" height="10" />
            </svg>
          </button>
          <button className="control-btn" title="Export">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8 12L3 7h3V3h4v4h3l-5 5z" />
              <path d="M2 13h12v2H2z" />
            </svg>
          </button>
        </div>
      </div>

      {/* Live Event Notifications */}
      <AnimatePresence>
        {activeEvents.length > 0 && (
          <div className="live-events">
            {activeEvents.map(event => (
              <motion.div
                key={event.id}
                className={`event-notification ${event.type}`}
                initial={{ opacity: 0, x: 50 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -50 }}
                transition={{ duration: 0.3 }}
              >
                <span className="event-icon">
                  {event.type === 'blocked' ? '🛡️' : '⚠️'}
                </span>
                <span className="event-text">
                  {event.count} threat{event.count > 1 ? 's' : ''} {event.type}
                </span>
                <span className="event-time">
                  {event.timestamp.toLocaleTimeString()}
                </span>
              </motion.div>
            ))}
          </div>
        )}
      </AnimatePresence>

      <div className="graph-wrapper">
        <Line data={chartData} options={options} />
      </div>

      <div className="activity-stats">
        <motion.div 
          className="stat-card"
          whileHover={{ scale: 1.05 }}
          transition={{ type: "spring", stiffness: 300 }}
        >
          <div className="stat-icon scans">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
            </svg>
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.totalScans.toLocaleString()}</div>
            <div className="stat-label">Total Scans</div>
          </div>
        </motion.div>

        <motion.div 
          className="stat-card"
          whileHover={{ scale: 1.05 }}
          transition={{ type: "spring", stiffness: 300 }}
        >
          <div className="stat-icon threats">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2L2 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-10-5z" />
              <path d="M11 10h2v5h-2z" fill="#fff" />
              <circle cx="12" cy="17" r="1" fill="#fff" />
            </svg>
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.totalThreats.toLocaleString()}</div>
            <div className="stat-label">Threats Detected</div>
          </div>
        </motion.div>

        <motion.div 
          className="stat-card"
          whileHover={{ scale: 1.05 }}
          transition={{ type: "spring", stiffness: 300 }}
        >
          <div className="stat-icon blocked">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zM4 12c0-4.42 3.58-8 8-8 1.85 0 3.55.63 4.9 1.69L5.69 16.9C4.63 15.55 4 13.85 4 12zm8 8c-1.85 0-3.55-.63-4.9-1.69L18.31 7.1C19.37 8.45 20 10.15 20 12c0 4.42-3.58 8-8 8z" />
            </svg>
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.totalBlocked.toLocaleString()}</div>
            <div className="stat-label">Threats Blocked</div>
          </div>
        </motion.div>

        <motion.div 
          className="stat-card"
          whileHover={{ scale: 1.05 }}
          transition={{ type: "spring", stiffness: 300 }}
        >
          <div className="stat-icon response">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
              <path d="M15 1H9v2h6V1zm-4 13h2V8h-2v6zm8.03-6.61l1.42-1.42c-.43-.51-.9-.99-1.41-1.41l-1.42 1.42C16.07 4.74 14.12 4 12 4c-4.97 0-9 4.03-9 9s4.02 9 9 9 9-4.03 9-9c0-2.12-.74-4.07-1.97-5.61zM12 20c-3.87 0-7-3.13-7-7s3.13-7 7-7 7 3.13 7 7-3.13 7-7 7z" />
            </svg>
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.avgResponseTime}ms</div>
            <div className="stat-label">Avg Response</div>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default ActivityGraph;
