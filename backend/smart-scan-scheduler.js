/**
 * Smart Scan Scheduling Engine
 * AI-optimized scan times based on system usage patterns
 * Machine learning to determine optimal scan schedules
 */

const fs = require('fs').promises;
const path = require('path');
const os = require('os');

class SmartScanScheduler {
  constructor() {
    this.usagePatterns = [];
    this.scheduledScans = new Map();
    this.scanHistory = [];
    this.systemMetrics = {
      cpu: [],
      memory: [],
      disk: [],
      network: []
    };
    
    // ML model parameters
    this.modelConfig = {
      learningRate: 0.01,
      trainingWindow: 168, // 1 week of hourly data
      predictionHorizon: 24, // hours
      optimalUsageThreshold: 0.3, // CPU usage below 30%
      minScanInterval: 3600000, // 1 hour minimum between scans
      adaptiveScheduling: true
    };

    // User preferences
    this.preferences = {
      scanDuration: 'auto', // auto, quick, full
      allowInterruption: false,
      preferredTimeRanges: [], // e.g., [{start: '22:00', end: '06:00'}]
      avoidTimeRanges: [], // e.g., work hours
      scanPriority: 'balanced', // aggressive, balanced, conservative
      maxCpuUsage: 50, // percentage
      maxMemoryUsage: 70 // percentage
    };

    // Scan types configuration
    this.scanTypes = {
      quick: {
        duration: 300000, // 5 minutes
        cpuUsage: 30,
        memoryUsage: 40,
        priority: 'low'
      },
      full: {
        duration: 3600000, // 1 hour
        cpuUsage: 60,
        memoryUsage: 70,
        priority: 'medium'
      },
      deep: {
        duration: 7200000, // 2 hours
        cpuUsage: 80,
        memoryUsage: 80,
        priority: 'high'
      },
      custom: {
        duration: 'variable',
        cpuUsage: 50,
        memoryUsage: 60,
        priority: 'medium'
      }
    };

    // Days of week mapping
    this.daysOfWeek = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

    this.initializeScheduler();
  }

  /**
   * Initialize the smart scheduler
   */
  async initializeScheduler() {
    console.log('🤖 Initializing Smart Scan Scheduler...');
    
    // Load historical data
    await this.loadHistoricalData();
    
    // Start monitoring system usage
    this.startMonitoring();
    
    // Analyze usage patterns
    await this.analyzeUsagePatterns();
    
    console.log('✅ Smart Scan Scheduler ready');
  }

  /**
   * Start monitoring system usage
   */
  startMonitoring() {
    // Collect metrics every 5 minutes
    this.monitoringInterval = setInterval(() => {
      this.collectSystemMetrics();
    }, 300000);

    console.log('📊 System usage monitoring started');
  }

  /**
   * Collect current system metrics
   */
  collectSystemMetrics() {
    const cpuUsage = this.calculateCpuUsage();
    const memoryUsage = 1 - (os.freemem() / os.totalmem());
    const timestamp = Date.now();
    const hour = new Date().getHours();
    const dayOfWeek = new Date().getDay();

    const metrics = {
      timestamp,
      hour,
      dayOfWeek,
      cpu: cpuUsage,
      memory: memoryUsage,
      idle: cpuUsage < 0.3 && memoryUsage < 0.5
    };

    // Store metrics
    this.systemMetrics.cpu.push({ timestamp, value: cpuUsage, hour, dayOfWeek });
    this.systemMetrics.memory.push({ timestamp, value: memoryUsage, hour, dayOfWeek });

    // Keep only recent data (7 days)
    const sevenDaysAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    Object.keys(this.systemMetrics).forEach(key => {
      this.systemMetrics[key] = this.systemMetrics[key].filter(
        m => m.timestamp > sevenDaysAgo
      );
    });

    return metrics;
  }

  /**
   * Analyze usage patterns using ML
   */
  async analyzeUsagePatterns() {
    if (this.systemMetrics.cpu.length < 20) {
      console.log('⏳ Collecting more data for pattern analysis...');
      return {
        status: 'insufficient_data',
        dataPoints: this.systemMetrics.cpu.length,
        requiredPoints: 20
      };
    }

    const patterns = {
      hourlyPatterns: {},
      dailyPatterns: {},
      optimalWindows: [],
      peakUsageTimes: [],
      idleTimes: []
    };

    // Analyze by hour of day
    for (let hour = 0; hour < 24; hour++) {
      const hourData = this.systemMetrics.cpu.filter(m => m.hour === hour);
      
      if (hourData.length > 0) {
        const avgCpu = hourData.reduce((sum, m) => sum + m.value, 0) / hourData.length;
        const avgMemory = this.systemMetrics.memory
          .filter(m => m.hour === hour)
          .reduce((sum, m) => sum + m.value, 0) / hourData.length;

        patterns.hourlyPatterns[hour] = {
          hour,
          avgCpu,
          avgMemory,
          samples: hourData.length,
          isOptimal: avgCpu < this.modelConfig.optimalUsageThreshold
        };

        // Identify optimal windows
        if (avgCpu < this.modelConfig.optimalUsageThreshold) {
          patterns.optimalWindows.push({
            hour,
            cpuUsage: avgCpu,
            memoryUsage: avgMemory,
            score: 1 - avgCpu // Lower usage = higher score
          });
        }

        // Identify peak usage times
        if (avgCpu > 0.7) {
          patterns.peakUsageTimes.push({
            hour,
            cpuUsage: avgCpu,
            memoryUsage: avgMemory
          });
        }
      }
    }

    // Analyze by day of week
    for (let day = 0; day < 7; day++) {
      const dayData = this.systemMetrics.cpu.filter(m => m.dayOfWeek === day);
      
      if (dayData.length > 0) {
        const avgCpu = dayData.reduce((sum, m) => sum + m.value, 0) / dayData.length;
        
        patterns.dailyPatterns[day] = {
          day: this.daysOfWeek[day],
          avgCpu,
          samples: dayData.length
        };
      }
    }

    // Sort optimal windows by score
    patterns.optimalWindows.sort((a, b) => b.score - a.score);

    // Find continuous idle time blocks
    patterns.idleTimes = this.findIdleTimeBlocks(patterns.hourlyPatterns);

    this.usagePatterns = patterns;
    return patterns;
  }

  /**
   * Find continuous blocks of idle time
   */
  findIdleTimeBlocks(hourlyPatterns) {
    const blocks = [];
    let currentBlock = null;

    for (let hour = 0; hour < 24; hour++) {
      const pattern = hourlyPatterns[hour];
      
      if (pattern && pattern.isOptimal) {
        if (currentBlock) {
          currentBlock.endHour = hour;
          currentBlock.duration++;
        } else {
          currentBlock = {
            startHour: hour,
            endHour: hour,
            duration: 1,
            avgCpu: pattern.avgCpu,
            avgMemory: pattern.avgMemory
          };
        }
      } else {
        if (currentBlock) {
          blocks.push(currentBlock);
          currentBlock = null;
        }
      }
    }

    // Handle wrap-around (end of day to start of day)
    if (currentBlock && blocks.length > 0 && blocks[0].startHour === 0) {
      blocks[0].startHour = currentBlock.startHour;
      blocks[0].duration += currentBlock.duration;
    } else if (currentBlock) {
      blocks.push(currentBlock);
    }

    return blocks.sort((a, b) => b.duration - a.duration);
  }

  /**
   * Generate optimal scan schedule
   */
  async generateOptimalSchedule(scanType = 'full', frequency = 'daily') {
    // Ensure we have usage patterns
    if (!this.usagePatterns.optimalWindows || this.usagePatterns.optimalWindows.length === 0) {
      await this.analyzeUsagePatterns();
    }

    const schedule = {
      scanType,
      frequency,
      recommendations: [],
      confidence: 0,
      reasoning: []
    };

    const scanConfig = this.scanTypes[scanType];
    const requiredDuration = scanConfig.duration;

    // Find optimal time slots
    const optimalSlots = this.findOptimalTimeSlots(requiredDuration, scanConfig);

    if (optimalSlots.length === 0) {
      schedule.recommendations.push({
        time: '02:00',
        dayOfWeek: 'daily',
        confidence: 0.5,
        reason: 'Default late-night schedule (insufficient usage data)'
      });
      schedule.confidence = 0.5;
      return schedule;
    }

    // Generate recommendations based on frequency
    if (frequency === 'daily') {
      const bestSlot = optimalSlots[0];
      schedule.recommendations.push({
        time: this.formatTime(bestSlot.hour),
        dayOfWeek: 'daily',
        confidence: bestSlot.confidence,
        reason: bestSlot.reason,
        estimatedDuration: this.formatDuration(requiredDuration),
        systemImpact: this.estimateSystemImpact(bestSlot, scanConfig)
      });
    } else if (frequency === 'weekly') {
      // Find best day of week
      const bestDay = this.findBestDayOfWeek();
      const bestSlot = optimalSlots[0];
      
      schedule.recommendations.push({
        time: this.formatTime(bestSlot.hour),
        dayOfWeek: this.daysOfWeek[bestDay],
        confidence: bestSlot.confidence,
        reason: bestSlot.reason,
        estimatedDuration: this.formatDuration(requiredDuration),
        systemImpact: this.estimateSystemImpact(bestSlot, scanConfig)
      });
    } else if (frequency === 'custom') {
      // Provide top 3 recommendations
      optimalSlots.slice(0, 3).forEach((slot, index) => {
        schedule.recommendations.push({
          time: this.formatTime(slot.hour),
          dayOfWeek: 'flexible',
          confidence: slot.confidence,
          reason: slot.reason,
          rank: index + 1
        });
      });
    }

    // Calculate overall confidence
    schedule.confidence = optimalSlots.length > 0 ? 
      optimalSlots[0].confidence : 0.5;

    // Add reasoning
    schedule.reasoning = this.generateScheduleReasoning(optimalSlots, scanConfig);

    return schedule;
  }

  /**
   * Find optimal time slots for scanning
   */
  findOptimalTimeSlots(requiredDuration, scanConfig) {
    const slots = [];
    const requiredHours = Math.ceil(requiredDuration / 3600000);

    // Check user preferences
    const preferredHours = this.getPreferredHours();
    const avoidHours = this.getAvoidHours();

    // Evaluate each hour
    for (let hour = 0; hour < 24; hour++) {
      // Skip avoided hours
      if (avoidHours.includes(hour)) continue;

      const pattern = this.usagePatterns.hourlyPatterns?.[hour];
      if (!pattern) continue;

      // Check if we have enough continuous idle time
      const hasEnoughTime = this.hasEnoughContinuousTime(hour, requiredHours);
      if (!hasEnoughTime) continue;

      // Calculate slot score
      let score = 1 - pattern.avgCpu; // Lower CPU = better

      // Boost score for preferred hours
      if (preferredHours.includes(hour)) {
        score *= 1.5;
      }

      // Check resource requirements
      if (pattern.avgCpu + (scanConfig.cpuUsage / 100) > 1) {
        score *= 0.5; // Penalize if scan would overload system
      }

      if (pattern.avgMemory + (scanConfig.memoryUsage / 100) > 0.9) {
        score *= 0.5;
      }

      // Calculate confidence
      const confidence = Math.min(
        pattern.samples / 20, // More samples = higher confidence
        score
      );

      slots.push({
        hour,
        score,
        confidence,
        cpuUsage: pattern.avgCpu,
        memoryUsage: pattern.avgMemory,
        reason: this.generateSlotReason(hour, pattern, score)
      });
    }

    // Sort by score
    return slots.sort((a, b) => b.score - a.score);
  }

  /**
   * Check if hour has enough continuous idle time
   */
  hasEnoughContinuousTime(startHour, requiredHours) {
    for (let i = 0; i < requiredHours; i++) {
      const hour = (startHour + i) % 24;
      const pattern = this.usagePatterns.hourlyPatterns?.[hour];
      
      if (!pattern || !pattern.isOptimal) {
        return false;
      }
    }
    return true;
  }

  /**
   * Get preferred hours based on user settings
   */
  getPreferredHours() {
    const hours = [];
    
    this.preferences.preferredTimeRanges.forEach(range => {
      const start = parseInt(range.start.split(':')[0]);
      const end = parseInt(range.end.split(':')[0]);
      
      for (let h = start; h !== end; h = (h + 1) % 24) {
        hours.push(h);
      }
    });

    return hours;
  }

  /**
   * Get hours to avoid based on user settings
   */
  getAvoidHours() {
    const hours = [];
    
    this.preferences.avoidTimeRanges.forEach(range => {
      const start = parseInt(range.start.split(':')[0]);
      const end = parseInt(range.end.split(':')[0]);
      
      for (let h = start; h !== end; h = (h + 1) % 24) {
        hours.push(h);
      }
    });

    return hours;
  }

  /**
   * Find best day of week for scanning
   */
  findBestDayOfWeek() {
    let bestDay = 0;
    let lowestUsage = Infinity;

    Object.entries(this.usagePatterns.dailyPatterns || {}).forEach(([day, pattern]) => {
      if (pattern.avgCpu < lowestUsage) {
        lowestUsage = pattern.avgCpu;
        bestDay = parseInt(day);
      }
    });

    return bestDay;
  }

  /**
   * Estimate system impact of scan
   */
  estimateSystemImpact(slot, scanConfig) {
    const totalCpu = slot.cpuUsage + (scanConfig.cpuUsage / 100);
    const totalMemory = slot.memoryUsage + (scanConfig.memoryUsage / 100);

    return {
      cpu: `${(totalCpu * 100).toFixed(1)}%`,
      memory: `${(totalMemory * 100).toFixed(1)}%`,
      level: totalCpu > 0.8 || totalMemory > 0.8 ? 'high' : 
             totalCpu > 0.5 || totalMemory > 0.6 ? 'medium' : 'low',
      userImpact: totalCpu > 0.7 ? 'noticeable' : 'minimal'
    };
  }

  /**
   * Generate reasoning for slot recommendation
   */
  generateSlotReason(hour, pattern, score) {
    const reasons = [];

    if (pattern.avgCpu < 0.2) {
      reasons.push('Very low CPU usage');
    } else if (pattern.avgCpu < 0.4) {
      reasons.push('Low CPU usage');
    }

    if (hour >= 22 || hour <= 6) {
      reasons.push('Typical off-hours period');
    }

    if (score > 0.8) {
      reasons.push('Optimal system conditions');
    }

    return reasons.join(', ');
  }

  /**
   * Generate schedule reasoning
   */
  generateScheduleReasoning(slots, scanConfig) {
    const reasoning = [];

    if (slots.length > 0) {
      reasoning.push(`Found ${slots.length} suitable time slots`);
      reasoning.push(`Based on ${this.systemMetrics.cpu.length} data points`);
      reasoning.push(`Scan requires approximately ${this.formatDuration(scanConfig.duration)}`);
    }

    if (this.usagePatterns.idleTimes?.length > 0) {
      const longestIdle = this.usagePatterns.idleTimes[0];
      reasoning.push(`Longest idle period: ${longestIdle.duration} hours starting at ${this.formatTime(longestIdle.startHour)}`);
    }

    return reasoning;
  }

  /**
   * Schedule a scan
   */
  async scheduleScan(scanType, schedule, options = {}) {
    const scanId = this.generateScanId();
    const nextRun = this.calculateNextRun(schedule);

    const scheduledScan = {
      id: scanId,
      scanType,
      schedule,
      nextRun,
      enabled: true,
      created: new Date().toISOString(),
      lastRun: null,
      runCount: 0,
      options,
      adaptive: this.modelConfig.adaptiveScheduling
    };

    this.scheduledScans.set(scanId, scheduledScan);

    console.log(`📅 Scan scheduled: ${scanType} at ${schedule.time} (ID: ${scanId})`);

    return scheduledScan;
  }

  /**
   * Calculate next run time
   */
  calculateNextRun(schedule) {
    const now = new Date();
    const [hours, minutes] = schedule.time.split(':').map(Number);
    
    const nextRun = new Date(now);
    nextRun.setHours(hours, minutes, 0, 0);

    // If time has passed today, schedule for tomorrow
    if (nextRun <= now) {
      nextRun.setDate(nextRun.getDate() + 1);
    }

    // Adjust for day of week if specified
    if (schedule.dayOfWeek && schedule.dayOfWeek !== 'daily' && schedule.dayOfWeek !== 'flexible') {
      const targetDay = this.daysOfWeek.indexOf(schedule.dayOfWeek);
      const currentDay = nextRun.getDay();
      const daysToAdd = (targetDay - currentDay + 7) % 7;
      nextRun.setDate(nextRun.getDate() + daysToAdd);
    }

    return nextRun.toISOString();
  }

  /**
   * Update schedule based on user behavior (adaptive learning)
   */
  async adaptSchedule(scanId) {
    const scan = this.scheduledScans.get(scanId);
    if (!scan || !scan.adaptive) return;

    // Re-analyze usage patterns
    const newPatterns = await this.analyzeUsagePatterns();

    // Generate new optimal schedule
    const newSchedule = await this.generateOptimalSchedule(
      scan.scanType,
      scan.schedule.frequency
    );

    // Update if significantly better
    if (newSchedule.confidence > scan.schedule.confidence + 0.1) {
      scan.schedule = newSchedule.recommendations[0];
      scan.nextRun = this.calculateNextRun(scan.schedule);
      
      console.log(`🔄 Adapted schedule for scan ${scanId}: ${scan.schedule.time}`);
    }
  }

  /**
   * Helper functions
   */

  calculateCpuUsage() {
    const cpus = os.cpus();
    let totalIdle = 0;
    let totalTick = 0;

    cpus.forEach(cpu => {
      for (let type in cpu.times) {
        totalTick += cpu.times[type];
      }
      totalIdle += cpu.times.idle;
    });

    return 1 - (totalIdle / totalTick);
  }

  formatTime(hour) {
    return `${hour.toString().padStart(2, '0')}:00`;
  }

  formatDuration(ms) {
    const hours = Math.floor(ms / 3600000);
    const minutes = Math.floor((ms % 3600000) / 60000);
    
    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
  }

  generateScanId() {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  async loadHistoricalData() {
    try {
      const dataPath = path.join(__dirname, 'data', 'scan-scheduler.json');
      const data = await fs.readFile(dataPath, 'utf8');
      const history = JSON.parse(data);
      
      this.systemMetrics = history.systemMetrics || this.systemMetrics;
      this.scanHistory = history.scanHistory || [];
    } catch (error) {
      // No historical data
    }
  }

  async saveData() {
    try {
      const dataPath = path.join(__dirname, 'data', 'scan-scheduler.json');
      await fs.writeFile(dataPath, JSON.stringify({
        systemMetrics: this.systemMetrics,
        scanHistory: this.scanHistory
      }, null, 2));
    } catch (error) {
      console.error('Failed to save scheduler data:', error);
    }
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      scheduledScans: this.scheduledScans.size,
      dataPoints: this.systemMetrics.cpu.length,
      optimalWindows: this.usagePatterns.optimalWindows?.length || 0,
      idleTimeBlocks: this.usagePatterns.idleTimes?.length || 0,
      scanHistory: this.scanHistory.length,
      preferences: this.preferences,
      modelConfig: this.modelConfig
    };
  }

  /**
   * Get all scheduled scans
   */
  getScheduledScans() {
    return Array.from(this.scheduledScans.values());
  }

  /**
   * Update user preferences
   */
  updatePreferences(newPreferences) {
    this.preferences = { ...this.preferences, ...newPreferences };
    console.log('✅ Scan preferences updated');
    return this.preferences;
  }

  /**
   * Stop monitoring
   */
  stopMonitoring() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      console.log('⏸️ System monitoring stopped');
    }
  }
}

// Export singleton
const smartScheduler = new SmartScanScheduler();
module.exports = smartScheduler;
