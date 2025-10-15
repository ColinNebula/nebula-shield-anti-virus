/**
 * Activity Logger Service
 * Tracks and logs all user activities and system events
 */

const fs = require('fs').promises;
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

class ActivityLogger {
  constructor() {
    this.db = null;
    this.dbPath = path.join(__dirname, 'data', 'activity.db');
    this.logFile = path.join(__dirname, 'logs', 'activity.log');
    this.initialized = false;
    this.maxLogAge = 90 * 24 * 60 * 60 * 1000; // 90 days
  }

  /**
   * Initialize activity logger
   */
  async initialize() {
    if (this.initialized) return;

    try {
      // Create directories
      await fs.mkdir(path.dirname(this.dbPath), { recursive: true });
      await fs.mkdir(path.dirname(this.logFile), { recursive: true });

      // Initialize database
      await this.initializeDatabase();
      
      this.initialized = true;
      console.log('✅ Activity logger initialized');
    } catch (error) {
      console.error('❌ Failed to initialize activity logger:', error);
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

        // Create activities table
        this.db.run(`
          CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            user_id INTEGER,
            user_email TEXT,
            action TEXT NOT NULL,
            category TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            status TEXT,
            duration INTEGER,
            metadata TEXT
          )
        `, (err) => {
          if (err) {
            reject(err);
            return;
          }

          // Create indexes
          this.db.run('CREATE INDEX IF NOT EXISTS idx_timestamp ON activities(timestamp)', (err) => {
            if (err) {
              reject(err);
              return;
            }

            this.db.run('CREATE INDEX IF NOT EXISTS idx_user ON activities(user_id)', (err) => {
              if (err) {
                reject(err);
              } else {
                resolve();
              }
            });
          });
        });
      });
    });
  }

  /**
   * Log activity
   */
  async log(activity) {
    await this.initialize();

    const {
      userId = null,
      userEmail = null,
      action,
      category,
      details = null,
      ipAddress = null,
      userAgent = null,
      status = 'success',
      duration = null,
      metadata = {}
    } = activity;

    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO activities (
          timestamp, user_id, user_email, action, category, 
          details, ip_address, user_agent, status, duration, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      this.db.run(sql, [
        Date.now(),
        userId,
        userEmail,
        action,
        category,
        details,
        ipAddress,
        userAgent,
        status,
        duration,
        JSON.stringify(metadata)
      ], function(err) {
        if (err) {
          console.error('Failed to log activity:', err);
          reject(err);
        } else {
          resolve(this.lastID);
        }
      });
    });

    // Also write to log file for backup
    this.writeToLogFile(activity);
  }

  /**
   * Write to log file
   */
  async writeToLogFile(activity) {
    try {
      const timestamp = new Date().toISOString();
      const logEntry = `[${timestamp}] ${activity.category}:${activity.action} - ${activity.details || ''} (User: ${activity.userEmail || 'System'})\n`;
      
      await fs.appendFile(this.logFile, logEntry);
    } catch (error) {
      console.error('Failed to write to log file:', error);
    }
  }

  /**
   * Get activities with filters
   */
  async getActivities(filters = {}) {
    await this.initialize();

    const {
      userId = null,
      category = null,
      action = null,
      startDate = null,
      endDate = null,
      status = null,
      limit = 100,
      offset = 0
    } = filters;

    let sql = 'SELECT * FROM activities WHERE 1=1';
    const params = [];

    if (userId) {
      sql += ' AND user_id = ?';
      params.push(userId);
    }

    if (category) {
      sql += ' AND category = ?';
      params.push(category);
    }

    if (action) {
      sql += ' AND action = ?';
      params.push(action);
    }

    if (startDate) {
      sql += ' AND timestamp >= ?';
      params.push(new Date(startDate).getTime());
    }

    if (endDate) {
      sql += ' AND timestamp <= ?';
      params.push(new Date(endDate).getTime());
    }

    if (status) {
      sql += ' AND status = ?';
      params.push(status);
    }

    sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) {
          reject(err);
        } else {
          const activities = rows.map(row => ({
            id: row.id,
            timestamp: new Date(row.timestamp),
            userId: row.user_id,
            userEmail: row.user_email,
            action: row.action,
            category: row.category,
            details: row.details,
            ipAddress: row.ip_address,
            userAgent: row.user_agent,
            status: row.status,
            duration: row.duration,
            metadata: row.metadata ? JSON.parse(row.metadata) : {}
          }));
          resolve(activities);
        }
      });
    });
  }

  /**
   * Get activity statistics
   */
  async getStatistics(userId = null, days = 30) {
    await this.initialize();

    const cutoffDate = Date.now() - (days * 24 * 60 * 60 * 1000);
    
    let sql = `
      SELECT 
        category,
        COUNT(*) as count,
        SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful,
        SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as failed
      FROM activities
      WHERE timestamp >= ?
    `;
    const params = [cutoffDate];

    if (userId) {
      sql += ' AND user_id = ?';
      params.push(userId);
    }

    sql += ' GROUP BY category';

    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) {
          reject(err);
        } else {
          const stats = {
            totalActivities: 0,
            successfulActivities: 0,
            failedActivities: 0,
            byCategory: {}
          };

          rows.forEach(row => {
            stats.totalActivities += row.count;
            stats.successfulActivities += row.successful;
            stats.failedActivities += row.failed;
            stats.byCategory[row.category] = {
              count: row.count,
              successful: row.successful,
              failed: row.failed
            };
          });

          resolve(stats);
        }
      });
    });
  }

  /**
   * Get recent activities
   */
  async getRecentActivities(userId = null, limit = 50) {
    return this.getActivities({
      userId,
      limit,
      offset: 0
    });
  }

  /**
   * Clean up old activities
   */
  async cleanupOldActivities(daysOld = 90) {
    await this.initialize();

    const cutoffDate = Date.now() - (daysOld * 24 * 60 * 60 * 1000);

    return new Promise((resolve, reject) => {
      this.db.run(
        'DELETE FROM activities WHERE timestamp < ?',
        [cutoffDate],
        function(err) {
          if (err) {
            reject(err);
          } else {
            console.log(`🧹 Cleaned up ${this.changes} old activity log(s)`);
            resolve(this.changes);
          }
        }
      );
    });
  }

  /**
   * Export activities to JSON
   */
  async exportActivities(filters = {}) {
    const activities = await this.getActivities({
      ...filters,
      limit: 10000 // Export up to 10k records
    });

    return {
      exportedAt: new Date().toISOString(),
      totalRecords: activities.length,
      filters: filters,
      activities: activities
    };
  }

  /**
   * Search activities
   */
  async searchActivities(searchTerm, limit = 100) {
    await this.initialize();

    return new Promise((resolve, reject) => {
      const sql = `
        SELECT * FROM activities 
        WHERE action LIKE ? OR details LIKE ? OR user_email LIKE ?
        ORDER BY timestamp DESC 
        LIMIT ?
      `;
      
      const searchPattern = `%${searchTerm}%`;

      this.db.all(sql, [searchPattern, searchPattern, searchPattern, limit], (err, rows) => {
        if (err) {
          reject(err);
        } else {
          const activities = rows.map(row => ({
            id: row.id,
            timestamp: new Date(row.timestamp),
            userId: row.user_id,
            userEmail: row.user_email,
            action: row.action,
            category: row.category,
            details: row.details,
            ipAddress: row.ip_address,
            userAgent: row.user_agent,
            status: row.status,
            duration: row.duration,
            metadata: row.metadata ? JSON.parse(row.metadata) : {}
          }));
          resolve(activities);
        }
      });
    });
  }

  /**
   * Close database
   */
  async close() {
    if (this.db) {
      return new Promise((resolve, reject) => {
        this.db.close((err) => {
          if (err) {
            reject(err);
          } else {
            console.log('✅ Activity logger database closed');
            resolve();
          }
        });
      });
    }
  }
}

// Singleton instance
const activityLogger = new ActivityLogger();

// Cleanup old activities daily
setInterval(async () => {
  try {
    await activityLogger.cleanupOldActivities(90);
  } catch (error) {
    console.error('Failed to cleanup old activities:', error);
  }
}, 24 * 60 * 60 * 1000);

module.exports = activityLogger;
