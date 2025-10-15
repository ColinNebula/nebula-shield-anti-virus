/**
 * Analytics Service
 * Tracks user behavior, system events, and application metrics
 */

const fs = require('fs').promises;
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

class AnalyticsService {
  constructor() {
    this.db = null;
    this.dbPath = path.join(__dirname, 'data', 'analytics.db');
    this.initialized = false;
    this.metricsCache = new Map();
    this.eventQueue = [];
    this.flushInterval = 5000; // Flush every 5 seconds
  }

  /**
   * Initialize analytics service
   */
  async initialize() {
    if (this.initialized) return;

    try {
      // Create data directory
      await fs.mkdir(path.dirname(this.dbPath), { recursive: true });

      // Initialize database
      await this.initializeDatabase();
      
      // Start event flushing
      this.startEventFlusher();
      
      this.initialized = true;
      console.log('✅ Analytics service initialized');
    } catch (error) {
      console.error('❌ Failed to initialize analytics service:', error);
      throw error;
    }
  }

  /**
   * Initialize SQLite database
   */
  async initializeDatabase() {
    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(this.dbPath, (err) => {
        if (err) {
          reject(err);
          return;
        }

        // Create tables
        const tables = [
          // Events table
          `CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            user_id INTEGER,
            session_id TEXT,
            event_type TEXT NOT NULL,
            event_name TEXT NOT NULL,
            event_data TEXT,
            page_url TEXT,
            referrer TEXT,
            user_agent TEXT,
            ip_address TEXT,
            metadata TEXT
          )`,
          
          // Page views table
          `CREATE TABLE IF NOT EXISTS page_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            user_id INTEGER,
            session_id TEXT,
            page_url TEXT NOT NULL,
            page_title TEXT,
            referrer TEXT,
            duration INTEGER,
            metadata TEXT
          )`,
          
          // User sessions table
          `CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            start_time INTEGER NOT NULL,
            end_time INTEGER,
            duration INTEGER,
            page_views INTEGER DEFAULT 0,
            events_count INTEGER DEFAULT 0,
            ip_address TEXT,
            user_agent TEXT,
            device_type TEXT,
            browser TEXT,
            os TEXT,
            metadata TEXT
          )`,
          
          // Performance metrics table
          `CREATE TABLE IF NOT EXISTS performance_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            metric_type TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            value REAL NOT NULL,
            unit TEXT,
            metadata TEXT
          )`,
          
          // Error logs table
          `CREATE TABLE IF NOT EXISTS error_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            user_id INTEGER,
            session_id TEXT,
            error_type TEXT NOT NULL,
            error_message TEXT NOT NULL,
            error_stack TEXT,
            component_name TEXT,
            page_url TEXT,
            severity TEXT,
            user_agent TEXT,
            metadata TEXT
          )`,
          
          // User metrics table
          `CREATE TABLE IF NOT EXISTS user_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            metric_type TEXT NOT NULL,
            metric_value REAL NOT NULL,
            metadata TEXT
          )`
        ];

        let completed = 0;
        tables.forEach(sql => {
          this.db.run(sql, (err) => {
            if (err) {
              reject(err);
              return;
            }
            completed++;
            if (completed === tables.length) {
              // Create indexes
              this.createIndexes().then(resolve).catch(reject);
            }
          });
        });
      });
    });
  }

  /**
   * Create database indexes
   */
  async createIndexes() {
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)',
      'CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)',
      'CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_pageviews_timestamp ON page_views(timestamp)',
      'CREATE INDEX IF NOT EXISTS idx_pageviews_user ON page_views(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_sessions_start ON user_sessions(start_time)',
      'CREATE INDEX IF NOT EXISTS idx_performance_timestamp ON performance_metrics(timestamp)',
      'CREATE INDEX IF NOT EXISTS idx_performance_type ON performance_metrics(metric_type)',
      'CREATE INDEX IF NOT EXISTS idx_errors_timestamp ON error_logs(timestamp)',
      'CREATE INDEX IF NOT EXISTS idx_errors_type ON error_logs(error_type)'
    ];

    for (const sql of indexes) {
      await new Promise((resolve, reject) => {
        this.db.run(sql, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }
  }

  /**
   * Track event
   */
  async trackEvent(event) {
    await this.initialize();

    const {
      userId = null,
      sessionId = null,
      eventType,
      eventName,
      eventData = {},
      pageUrl = null,
      referrer = null,
      userAgent = null,
      ipAddress = null,
      metadata = {}
    } = event;

    this.eventQueue.push({
      timestamp: Date.now(),
      userId,
      sessionId,
      eventType,
      eventName,
      eventData: JSON.stringify(eventData),
      pageUrl,
      referrer,
      userAgent,
      ipAddress,
      metadata: JSON.stringify(metadata)
    });

    // If queue is getting large, flush immediately
    if (this.eventQueue.length >= 50) {
      await this.flushEvents();
    }
  }

  /**
   * Track page view
   */
  async trackPageView(pageView) {
    await this.initialize();

    const {
      userId = null,
      sessionId = null,
      pageUrl,
      pageTitle = null,
      referrer = null,
      duration = null,
      metadata = {}
    } = pageView;

    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO page_views (
          timestamp, user_id, session_id, page_url, page_title,
          referrer, duration, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;

      this.db.run(sql, [
        Date.now(),
        userId,
        sessionId,
        pageUrl,
        pageTitle,
        referrer,
        duration,
        JSON.stringify(metadata)
      ], function(err) {
        if (err) {
          console.error('Failed to track page view:', err);
          reject(err);
        } else {
          resolve(this.lastID);
        }
      });
    });
  }

  /**
   * Start or update user session
   */
  async trackSession(session) {
    await this.initialize();

    const {
      sessionId,
      userId = null,
      startTime = Date.now(),
      endTime = null,
      ipAddress = null,
      userAgent = null,
      deviceType = null,
      browser = null,
      os = null,
      metadata = {}
    } = session;

    return new Promise((resolve, reject) => {
      // Check if session exists
      this.db.get(
        'SELECT * FROM user_sessions WHERE session_id = ?',
        [sessionId],
        (err, row) => {
          if (err) {
            reject(err);
            return;
          }

          if (row) {
            // Update existing session
            const duration = endTime ? endTime - row.start_time : null;
            this.db.run(
              `UPDATE user_sessions SET 
                end_time = ?, duration = ?, page_views = page_views + 1,
                events_count = events_count + 1, metadata = ?
               WHERE session_id = ?`,
              [endTime, duration, JSON.stringify(metadata), sessionId],
              function(err) {
                if (err) reject(err);
                else resolve(row.id);
              }
            );
          } else {
            // Create new session
            this.db.run(
              `INSERT INTO user_sessions (
                session_id, user_id, start_time, ip_address, user_agent,
                device_type, browser, os, metadata
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                sessionId, userId, startTime, ipAddress, userAgent,
                deviceType, browser, os, JSON.stringify(metadata)
              ],
              function(err) {
                if (err) reject(err);
                else resolve(this.lastID);
              }
            );
          }
        }
      );
    });
  }

  /**
   * Log error
   */
  async logError(error) {
    await this.initialize();

    const {
      userId = null,
      sessionId = null,
      errorType,
      errorMessage,
      errorStack = null,
      componentName = null,
      pageUrl = null,
      severity = 'error',
      userAgent = null,
      metadata = {}
    } = error;

    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO error_logs (
          timestamp, user_id, session_id, error_type, error_message,
          error_stack, component_name, page_url, severity, user_agent, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      this.db.run(sql, [
        Date.now(),
        userId,
        sessionId,
        errorType,
        errorMessage,
        errorStack,
        componentName,
        pageUrl,
        severity,
        userAgent,
        JSON.stringify(metadata)
      ], function(err) {
        if (err) {
          console.error('Failed to log error:', err);
          reject(err);
        } else {
          resolve(this.lastID);
        }
      });
    });
  }

  /**
   * Track performance metric
   */
  async trackPerformance(metric) {
    await this.initialize();

    const {
      metricType,
      metricName,
      value,
      unit = 'ms',
      metadata = {}
    } = metric;

    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO performance_metrics (
          timestamp, metric_type, metric_name, value, unit, metadata
        ) VALUES (?, ?, ?, ?, ?, ?)
      `;

      this.db.run(sql, [
        Date.now(),
        metricType,
        metricName,
        value,
        unit,
        JSON.stringify(metadata)
      ], function(err) {
        if (err) {
          console.error('Failed to track performance:', err);
          reject(err);
        } else {
          resolve(this.lastID);
        }
      });
    });
  }

  /**
   * Flush event queue to database
   */
  async flushEvents() {
    if (this.eventQueue.length === 0) return;

    const events = [...this.eventQueue];
    this.eventQueue = [];

    const sql = `
      INSERT INTO events (
        timestamp, user_id, session_id, event_type, event_name,
        event_data, page_url, referrer, user_agent, ip_address, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    for (const event of events) {
      await new Promise((resolve, reject) => {
        this.db.run(sql, [
          event.timestamp,
          event.userId,
          event.sessionId,
          event.eventType,
          event.eventName,
          event.eventData,
          event.pageUrl,
          event.referrer,
          event.userAgent,
          event.ipAddress,
          event.metadata
        ], (err) => {
          if (err) console.error('Failed to flush event:', err);
          resolve();
        });
      });
    }
  }

  /**
   * Start automatic event flushing
   */
  startEventFlusher() {
    setInterval(() => {
      this.flushEvents().catch(err => {
        console.error('Failed to flush events:', err);
      });
    }, this.flushInterval);
  }

  /**
   * Get analytics dashboard data
   */
  async getDashboardData(timeRange = '24h') {
    await this.initialize();

    const cutoffTime = this.getTimeRangeCutoff(timeRange);

    const [
      totalEvents,
      totalPageViews,
      activeSessions,
      totalErrors,
      avgSessionDuration,
      topEvents,
      topPages,
      errorsByType,
      performanceMetrics
    ] = await Promise.all([
      this.getTotalEvents(cutoffTime),
      this.getTotalPageViews(cutoffTime),
      this.getActiveSessions(cutoffTime),
      this.getTotalErrors(cutoffTime),
      this.getAvgSessionDuration(cutoffTime),
      this.getTopEvents(cutoffTime),
      this.getTopPages(cutoffTime),
      this.getErrorsByType(cutoffTime),
      this.getPerformanceMetrics(cutoffTime)
    ]);

    return {
      overview: {
        totalEvents,
        totalPageViews,
        activeSessions,
        totalErrors,
        avgSessionDuration
      },
      topEvents,
      topPages,
      errorsByType,
      performanceMetrics,
      timeRange
    };
  }

  /**
   * Get time range cutoff timestamp
   */
  getTimeRangeCutoff(timeRange) {
    const now = Date.now();
    const ranges = {
      '1h': 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
      '30d': 30 * 24 * 60 * 60 * 1000
    };
    return now - (ranges[timeRange] || ranges['24h']);
  }

  /**
   * Helper query functions
   */
  async getTotalEvents(cutoff) {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT COUNT(*) as count FROM events WHERE timestamp >= ?',
        [cutoff],
        (err, row) => {
          if (err) reject(err);
          else resolve(row.count);
        }
      );
    });
  }

  async getTotalPageViews(cutoff) {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT COUNT(*) as count FROM page_views WHERE timestamp >= ?',
        [cutoff],
        (err, row) => {
          if (err) reject(err);
          else resolve(row.count);
        }
      );
    });
  }

  async getActiveSessions(cutoff) {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT COUNT(*) as count FROM user_sessions WHERE start_time >= ?',
        [cutoff],
        (err, row) => {
          if (err) reject(err);
          else resolve(row.count);
        }
      );
    });
  }

  async getTotalErrors(cutoff) {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT COUNT(*) as count FROM error_logs WHERE timestamp >= ?',
        [cutoff],
        (err, row) => {
          if (err) reject(err);
          else resolve(row.count);
        }
      );
    });
  }

  async getAvgSessionDuration(cutoff) {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT AVG(duration) as avg FROM user_sessions WHERE start_time >= ? AND duration IS NOT NULL',
        [cutoff],
        (err, row) => {
          if (err) reject(err);
          else resolve(row.avg || 0);
        }
      );
    });
  }

  async getTopEvents(cutoff, limit = 10) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT event_name, COUNT(*) as count 
         FROM events 
         WHERE timestamp >= ? 
         GROUP BY event_name 
         ORDER BY count DESC 
         LIMIT ?`,
        [cutoff, limit],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  async getTopPages(cutoff, limit = 10) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT page_url, COUNT(*) as views 
         FROM page_views 
         WHERE timestamp >= ? 
         GROUP BY page_url 
         ORDER BY views DESC 
         LIMIT ?`,
        [cutoff, limit],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  async getErrorsByType(cutoff) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT error_type, severity, COUNT(*) as count 
         FROM error_logs 
         WHERE timestamp >= ? 
         GROUP BY error_type, severity 
         ORDER BY count DESC`,
        [cutoff],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  async getPerformanceMetrics(cutoff) {
    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT metric_type, metric_name, AVG(value) as avg_value, MIN(value) as min_value, MAX(value) as max_value, unit
         FROM performance_metrics 
         WHERE timestamp >= ? 
         GROUP BY metric_type, metric_name 
         ORDER BY metric_type, metric_name`,
        [cutoff],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  /**
   * Get error timeline
   */
  async getErrorTimeline(timeRange = '24h', interval = '1h') {
    await this.initialize();
    
    const cutoff = this.getTimeRangeCutoff(timeRange);
    const intervalMs = this.getIntervalMs(interval);

    return new Promise((resolve, reject) => {
      this.db.all(
        `SELECT 
          (timestamp / ?) * ? as time_bucket,
          severity,
          COUNT(*) as count
         FROM error_logs
         WHERE timestamp >= ?
         GROUP BY time_bucket, severity
         ORDER BY time_bucket ASC`,
        [intervalMs, intervalMs, cutoff],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        }
      );
    });
  }

  getIntervalMs(interval) {
    const intervals = {
      '1m': 60 * 1000,
      '5m': 5 * 60 * 1000,
      '15m': 15 * 60 * 1000,
      '1h': 60 * 60 * 1000,
      '1d': 24 * 60 * 60 * 1000
    };
    return intervals[interval] || intervals['1h'];
  }

  /**
   * Cleanup old data
   */
  async cleanupOldData(daysOld = 90) {
    await this.initialize();

    const cutoff = Date.now() - (daysOld * 24 * 60 * 60 * 1000);

    const tables = ['events', 'page_views', 'user_sessions', 'performance_metrics', 'error_logs'];
    let totalDeleted = 0;

    for (const table of tables) {
      const deleted = await new Promise((resolve, reject) => {
        this.db.run(
          `DELETE FROM ${table} WHERE timestamp < ?`,
          [cutoff],
          function(err) {
            if (err) reject(err);
            else resolve(this.changes);
          }
        );
      });
      totalDeleted += deleted;
    }

    console.log(`🧹 Cleaned up ${totalDeleted} old analytics record(s)`);
    return totalDeleted;
  }

  /**
   * Close database
   */
  async close() {
    if (this.db) {
      await this.flushEvents();
      return new Promise((resolve, reject) => {
        this.db.close((err) => {
          if (err) reject(err);
          else {
            console.log('✅ Analytics database closed');
            resolve();
          }
        });
      });
    }
  }
}

// Singleton instance
const analyticsService = new AnalyticsService();

// Cleanup old data daily
setInterval(async () => {
  try {
    await analyticsService.cleanupOldData(90);
  } catch (error) {
    console.error('Failed to cleanup old analytics data:', error);
  }
}, 24 * 60 * 60 * 1000);

module.exports = analyticsService;
