/**
 * Scheduled Tasks Service
 * Handles scheduled scans, cleanups, and maintenance tasks
 */

const EventEmitter = require('events');
const cron = require('node-cron');
const fs = require('fs');
const path = require('path');

class ScheduledTasksService extends EventEmitter {
  constructor() {
    super();
    this.tasks = new Map();
    this.schedules = new Map();
    this.taskHistory = [];
    this.configPath = path.join(process.cwd(), 'data', 'scheduled-tasks.json');
    this.maxHistorySize = 1000;
    
    this.initialize();
  }

  /**
   * Initialize service and load saved tasks
   */
  initialize() {
    // Ensure data directory exists
    const dataDir = path.dirname(this.configPath);
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    // Load saved tasks
    this.loadTasks();
    
    // Start cleanup interval
    this.startCleanup();
  }

  /**
   * Create a new scheduled task
   */
  createTask(taskConfig) {
    const task = {
      id: `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      name: taskConfig.name,
      type: taskConfig.type, // scan, cleanup, backup, update
      schedule: taskConfig.schedule, // cron expression
      enabled: taskConfig.enabled !== false,
      options: taskConfig.options || {},
      createdAt: Date.now(),
      lastRun: null,
      nextRun: null,
      runCount: 0,
      successCount: 0,
      failureCount: 0,
      lastStatus: null,
      lastError: null
    };

    // Validate cron expression
    if (!cron.validate(task.schedule)) {
      throw new Error(`Invalid cron expression: ${task.schedule}`);
    }

    this.tasks.set(task.id, task);
    
    if (task.enabled) {
      this.scheduleTask(task);
    }

    this.saveTasks();
    this.emit('task:created', task);

    return task;
  }

  /**
   * Schedule a task
   */
  scheduleTask(task) {
    // Remove existing schedule if any
    if (this.schedules.has(task.id)) {
      this.schedules.get(task.id).stop();
    }

    // Create new schedule
    const schedule = cron.schedule(task.schedule, async () => {
      await this.executeTask(task.id);
    }, {
      scheduled: true,
      timezone: 'UTC'
    });

    this.schedules.set(task.id, schedule);
    
    // Calculate next run time
    task.nextRun = this.getNextRunTime(task.schedule);
    
    this.emit('task:scheduled', task);
  }

  /**
   * Execute a task
   */
  async executeTask(taskId, manualRun = false) {
    const task = this.tasks.get(taskId);
    
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }

    const execution = {
      taskId: task.id,
      taskName: task.name,
      taskType: task.type,
      startTime: Date.now(),
      endTime: null,
      duration: null,
      status: 'running',
      result: null,
      error: null,
      manualRun
    };

    this.emit('task:started', { task, execution });

    try {
      // Execute task based on type
      let result;
      
      switch (task.type) {
        case 'scan':
          result = await this.executeScan(task.options);
          break;
        case 'cleanup':
          result = await this.executeCleanup(task.options);
          break;
        case 'backup':
          result = await this.executeBackup(task.options);
          break;
        case 'update':
          result = await this.executeUpdate(task.options);
          break;
        case 'custom':
          result = await this.executeCustom(task.options);
          break;
        default:
          throw new Error(`Unknown task type: ${task.type}`);
      }

      execution.status = 'success';
      execution.result = result;
      task.successCount++;
      task.lastStatus = 'success';
      task.lastError = null;
      
    } catch (error) {
      execution.status = 'failed';
      execution.error = error.message;
      task.failureCount++;
      task.lastStatus = 'failed';
      task.lastError = error.message;
      
      this.emit('task:failed', { task, execution, error });
    }

    execution.endTime = Date.now();
    execution.duration = execution.endTime - execution.startTime;
    
    // Update task stats
    task.runCount++;
    task.lastRun = execution.endTime;
    task.nextRun = this.getNextRunTime(task.schedule);

    // Add to history
    this.addToHistory(execution);
    
    this.saveTasks();
    this.emit('task:completed', { task, execution });

    return execution;
  }

  /**
   * Execute scan task
   */
  async executeScan(options) {
    // Simulate scan execution
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          type: 'scan',
          scannedFiles: Math.floor(Math.random() * 1000) + 500,
          threatsFound: Math.floor(Math.random() * 5),
          cleanedFiles: Math.floor(Math.random() * 3),
          duration: Date.now()
        });
      }, 1000);
    });
  }

  /**
   * Execute cleanup task
   */
  async executeCleanup(options) {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          type: 'cleanup',
          filesDeleted: Math.floor(Math.random() * 50) + 10,
          spaceFreed: Math.floor(Math.random() * 1024 * 1024 * 100),
          duration: Date.now()
        });
      }, 500);
    });
  }

  /**
   * Execute backup task
   */
  async executeBackup(options) {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          type: 'backup',
          filesBackedUp: Math.floor(Math.random() * 100) + 50,
          backupSize: Math.floor(Math.random() * 1024 * 1024 * 500),
          backupLocation: options.location || 'default',
          duration: Date.now()
        });
      }, 800);
    });
  }

  /**
   * Execute update task
   */
  async executeUpdate(options) {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          type: 'update',
          updatesInstalled: Math.floor(Math.random() * 3),
          currentVersion: '1.0.0',
          newVersion: '1.0.1',
          duration: Date.now()
        });
      }, 1500);
    });
  }

  /**
   * Execute custom task
   */
  async executeCustom(options) {
    if (typeof options.handler === 'function') {
      return await options.handler(options);
    }
    
    throw new Error('Custom task requires a handler function');
  }

  /**
   * Get task by ID
   */
  getTask(taskId) {
    return this.tasks.get(taskId);
  }

  /**
   * Get all tasks
   */
  getAllTasks() {
    return Array.from(this.tasks.values());
  }

  /**
   * Update task
   */
  updateTask(taskId, updates) {
    const task = this.tasks.get(taskId);
    
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }

    // Update fields
    if (updates.name) task.name = updates.name;
    if (updates.schedule) {
      if (!cron.validate(updates.schedule)) {
        throw new Error(`Invalid cron expression: ${updates.schedule}`);
      }
      task.schedule = updates.schedule;
    }
    if (updates.options) task.options = { ...task.options, ...updates.options };
    if (typeof updates.enabled !== 'undefined') {
      task.enabled = updates.enabled;
    }

    // Reschedule if enabled
    if (task.enabled) {
      this.scheduleTask(task);
    } else {
      // Stop schedule if disabled
      if (this.schedules.has(taskId)) {
        this.schedules.get(taskId).stop();
        this.schedules.delete(taskId);
      }
    }

    this.saveTasks();
    this.emit('task:updated', task);

    return task;
  }

  /**
   * Delete task
   */
  deleteTask(taskId) {
    const task = this.tasks.get(taskId);
    
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }

    // Stop schedule
    if (this.schedules.has(taskId)) {
      this.schedules.get(taskId).stop();
      this.schedules.delete(taskId);
    }

    this.tasks.delete(taskId);
    this.saveTasks();
    this.emit('task:deleted', { taskId });

    return true;
  }

  /**
   * Enable/disable task
   */
  toggleTask(taskId, enabled) {
    return this.updateTask(taskId, { enabled });
  }

  /**
   * Get task history
   */
  getHistory(filters = {}) {
    let history = [...this.taskHistory];

    if (filters.taskId) {
      history = history.filter(h => h.taskId === filters.taskId);
    }

    if (filters.status) {
      history = history.filter(h => h.status === filters.status);
    }

    if (filters.limit) {
      history = history.slice(0, filters.limit);
    }

    return history;
  }

  /**
   * Add execution to history
   */
  addToHistory(execution) {
    this.taskHistory.unshift(execution);
    
    // Limit history size
    if (this.taskHistory.length > this.maxHistorySize) {
      this.taskHistory = this.taskHistory.slice(0, this.maxHistorySize);
    }
  }

  /**
   * Get task statistics
   */
  getStatistics() {
    const tasks = Array.from(this.tasks.values());
    
    return {
      totalTasks: tasks.length,
      enabledTasks: tasks.filter(t => t.enabled).length,
      disabledTasks: tasks.filter(t => !t.enabled).length,
      totalRuns: tasks.reduce((sum, t) => sum + t.runCount, 0),
      successfulRuns: tasks.reduce((sum, t) => sum + t.successCount, 0),
      failedRuns: tasks.reduce((sum, t) => sum + t.failureCount, 0),
      successRate: this.calculateSuccessRate(tasks),
      tasksByType: this.groupTasksByType(tasks),
      recentExecutions: this.taskHistory.slice(0, 10)
    };
  }

  /**
   * Calculate success rate
   */
  calculateSuccessRate(tasks) {
    const total = tasks.reduce((sum, t) => sum + t.runCount, 0);
    const successful = tasks.reduce((sum, t) => sum + t.successCount, 0);
    
    return total > 0 ? Math.round((successful / total) * 100) : 0;
  }

  /**
   * Group tasks by type
   */
  groupTasksByType(tasks) {
    const grouped = {};
    
    tasks.forEach(task => {
      if (!grouped[task.type]) {
        grouped[task.type] = 0;
      }
      grouped[task.type]++;
    });
    
    return grouped;
  }

  /**
   * Get next run time for cron expression
   */
  getNextRunTime(cronExpression) {
    try {
      const schedule = cron.schedule(cronExpression, () => {}, { scheduled: false });
      // This is a simplified version - in production use a library like node-cron-parser
      return Date.now() + 60000; // Placeholder: 1 minute from now
    } catch (error) {
      return null;
    }
  }

  /**
   * Save tasks to file
   */
  saveTasks() {
    const data = {
      tasks: Array.from(this.tasks.values()),
      savedAt: Date.now()
    };

    try {
      fs.writeFileSync(this.configPath, JSON.stringify(data, null, 2), 'utf8');
    } catch (error) {
      console.error('Failed to save tasks:', error);
    }
  }

  /**
   * Load tasks from file
   */
  loadTasks() {
    try {
      if (fs.existsSync(this.configPath)) {
        const data = JSON.parse(fs.readFileSync(this.configPath, 'utf8'));
        
        if (data.tasks && Array.isArray(data.tasks)) {
          data.tasks.forEach(task => {
            this.tasks.set(task.id, task);
            
            if (task.enabled) {
              this.scheduleTask(task);
            }
          });
        }
      }
    } catch (error) {
      console.error('Failed to load tasks:', error);
    }
  }

  /**
   * Start cleanup interval
   */
  startCleanup() {
    // Clean up old history every hour
    setInterval(() => {
      const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
      this.taskHistory = this.taskHistory.filter(h => h.endTime > oneWeekAgo);
    }, 60 * 60 * 1000);
  }

  /**
   * Export tasks configuration
   */
  exportTasks() {
    return {
      tasks: Array.from(this.tasks.values()),
      exportedAt: Date.now(),
      version: '1.0.0'
    };
  }

  /**
   * Import tasks configuration
   */
  importTasks(config) {
    if (!config.tasks || !Array.isArray(config.tasks)) {
      throw new Error('Invalid tasks configuration');
    }

    let imported = 0;
    
    config.tasks.forEach(taskConfig => {
      try {
        // Generate new ID to avoid conflicts
        const newTask = { ...taskConfig };
        delete newTask.id;
        
        this.createTask(newTask);
        imported++;
      } catch (error) {
        console.error(`Failed to import task: ${error.message}`);
      }
    });

    return { imported, total: config.tasks.length };
  }
}

// Singleton instance
const scheduledTasksService = new ScheduledTasksService();

module.exports = scheduledTasksService;
