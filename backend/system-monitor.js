/**
 * System Health Monitoring Service
 * Monitors CPU, memory, disk, network, and application health
 */

const os = require('os');
const fs = require('fs').promises;
const path = require('path');
const { execSync } = require('child_process');

class SystemMonitor {
  constructor() {
    this.metrics = {
      cpu: [],
      memory: [],
      disk: [],
      network: [],
      processes: []
    };
    this.maxHistorySize = 100;
    this.alertThresholds = {
      cpu: 80,
      memory: 85,
      disk: 90,
      errorRate: 5
    };
    this.alerts = [];
  }

  /**
   * Get system health overview
   */
  async getSystemHealth() {
    const [cpu, memory, disk, network, processes] = await Promise.all([
      this.getCPUMetrics(),
      this.getMemoryMetrics(),
      this.getDiskMetrics(),
      this.getNetworkMetrics(),
      this.getProcessMetrics()
    ]);

    const health = this.calculateHealthScore({ cpu, memory, disk });

    return {
      timestamp: new Date().toISOString(),
      health,
      cpu,
      memory,
      disk,
      network,
      processes,
      alerts: this.getActiveAlerts()
    };
  }

  /**
   * Get CPU metrics
   */
  async getCPUMetrics() {
    const cpus = os.cpus();
    
    // Calculate CPU usage
    let totalIdle = 0;
    let totalTick = 0;

    cpus.forEach(cpu => {
      for (const type in cpu.times) {
        totalTick += cpu.times[type];
      }
      totalIdle += cpu.times.idle;
    });

    const idle = totalIdle / cpus.length;
    const total = totalTick / cpus.length;
    const usage = 100 - ~~(100 * idle / total);

    const metrics = {
      cores: cpus.length,
      model: cpus[0].model,
      speed: cpus[0].speed,
      usage: usage,
      loadAverage: os.loadavg(),
      temperature: await this.getCPUTemperature()
    };

    // Check threshold
    if (usage > this.alertThresholds.cpu) {
      this.addAlert('cpu', 'warning', `CPU usage at ${usage}%`);
    }

    // Store history
    this.addToHistory('cpu', { timestamp: Date.now(), usage });

    return metrics;
  }

  /**
   * Get CPU temperature (if available)
   */
  async getCPUTemperature() {
    try {
      if (process.platform === 'win32') {
        // Windows - use WMIC
        const output = execSync('wmic /namespace:\\\\root\\wmi PATH MSAcpi_ThermalZoneTemperature get CurrentTemperature', { encoding: 'utf8' });
        const temp = parseInt(output.split('\n')[1]);
        return temp ? (temp / 10 - 273.15).toFixed(1) : null;
      } else if (process.platform === 'linux') {
        // Linux - read from thermal zone
        const temp = await fs.readFile('/sys/class/thermal/thermal_zone0/temp', 'utf8');
        return (parseInt(temp) / 1000).toFixed(1);
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Get memory metrics
   */
  async getMemoryMetrics() {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const usagePercent = (usedMem / totalMem) * 100;

    const metrics = {
      total: totalMem,
      free: freeMem,
      used: usedMem,
      usagePercent: usagePercent.toFixed(2),
      processMemory: process.memoryUsage()
    };

    // Check threshold
    if (usagePercent > this.alertThresholds.memory) {
      this.addAlert('memory', 'warning', `Memory usage at ${usagePercent.toFixed(1)}%`);
    }

    // Store history
    this.addToHistory('memory', { timestamp: Date.now(), usage: usagePercent });

    return metrics;
  }

  /**
   * Get disk metrics
   */
  async getDiskMetrics() {
    try {
      let diskInfo = { total: 0, free: 0, used: 0, usagePercent: 0 };

      if (process.platform === 'win32') {
        // Windows - use WMIC
        const output = execSync('wmic logicaldisk get size,freespace,caption', { encoding: 'utf8' });
        const lines = output.split('\n').filter(line => line.trim());
        
        if (lines.length > 1) {
          const parts = lines[1].trim().split(/\s+/);
          if (parts.length >= 3) {
            const free = parseInt(parts[1]);
            const total = parseInt(parts[2]);
            const used = total - free;
            diskInfo = {
              total,
              free,
              used,
              usagePercent: ((used / total) * 100).toFixed(2)
            };
          }
        }
      } else {
        // Linux/Mac - use df
        const output = execSync('df -k /', { encoding: 'utf8' });
        const lines = output.split('\n');
        if (lines.length > 1) {
          const parts = lines[1].trim().split(/\s+/);
          const total = parseInt(parts[1]) * 1024;
          const used = parseInt(parts[2]) * 1024;
          const free = parseInt(parts[3]) * 1024;
          diskInfo = {
            total,
            free,
            used,
            usagePercent: ((used / total) * 100).toFixed(2)
          };
        }
      }

      // Check threshold
      if (parseFloat(diskInfo.usagePercent) > this.alertThresholds.disk) {
        this.addAlert('disk', 'critical', `Disk usage at ${diskInfo.usagePercent}%`);
      }

      // Store history
      this.addToHistory('disk', { timestamp: Date.now(), usage: parseFloat(diskInfo.usagePercent) });

      return diskInfo;
    } catch (error) {
      console.error('Failed to get disk metrics:', error);
      return { total: 0, free: 0, used: 0, usagePercent: 0, error: error.message };
    }
  }

  /**
   * Get network metrics
   */
  async getNetworkMetrics() {
    const networkInterfaces = os.networkInterfaces();
    const interfaces = [];

    for (const [name, addrs] of Object.entries(networkInterfaces)) {
      const ipv4 = addrs.find(addr => addr.family === 'IPv4');
      if (ipv4) {
        interfaces.push({
          name,
          address: ipv4.address,
          netmask: ipv4.netmask,
          mac: ipv4.mac
        });
      }
    }

    return {
      interfaces,
      hostname: os.hostname()
    };
  }

  /**
   * Get process metrics
   */
  async getProcessMetrics() {
    const uptime = process.uptime();
    const memUsage = process.memoryUsage();

    return {
      uptime,
      pid: process.pid,
      version: process.version,
      platform: process.platform,
      arch: process.arch,
      memory: {
        rss: memUsage.rss,
        heapTotal: memUsage.heapTotal,
        heapUsed: memUsage.heapUsed,
        external: memUsage.external
      }
    };
  }

  /**
   * Calculate overall health score
   */
  calculateHealthScore(metrics) {
    let score = 100;
    let status = 'healthy';

    // CPU impact
    if (metrics.cpu.usage > 90) {
      score -= 30;
      status = 'critical';
    } else if (metrics.cpu.usage > 75) {
      score -= 15;
      status = status === 'healthy' ? 'warning' : status;
    }

    // Memory impact
    const memUsage = parseFloat(metrics.memory.usagePercent);
    if (memUsage > 90) {
      score -= 30;
      status = 'critical';
    } else if (memUsage > 80) {
      score -= 15;
      status = status === 'healthy' ? 'warning' : status;
    }

    // Disk impact
    const diskUsage = parseFloat(metrics.disk.usagePercent);
    if (diskUsage > 95) {
      score -= 20;
      status = 'critical';
    } else if (diskUsage > 85) {
      score -= 10;
      status = status === 'healthy' ? 'warning' : status;
    }

    return {
      score: Math.max(0, score),
      status,
      message: this.getHealthMessage(status, score)
    };
  }

  /**
   * Get health message
   */
  getHealthMessage(status, score) {
    if (status === 'critical') {
      return 'System resources critically low. Immediate action required.';
    } else if (status === 'warning') {
      return 'System resources elevated. Monitor closely.';
    } else {
      return 'System operating normally.';
    }
  }

  /**
   * Add metric to history
   */
  addToHistory(type, metric) {
    if (!this.metrics[type]) {
      this.metrics[type] = [];
    }

    this.metrics[type].push(metric);

    // Keep only last N entries
    if (this.metrics[type].length > this.maxHistorySize) {
      this.metrics[type].shift();
    }
  }

  /**
   * Get metric history
   */
  getHistory(type, limit = 50) {
    if (!this.metrics[type]) {
      return [];
    }

    return this.metrics[type].slice(-limit);
  }

  /**
   * Add alert
   */
  addAlert(type, severity, message) {
    const alert = {
      id: Date.now(),
      type,
      severity,
      message,
      timestamp: new Date().toISOString()
    };

    // Don't add duplicate alerts within 5 minutes
    const recentAlert = this.alerts.find(
      a => a.type === type && a.severity === severity && 
      (Date.now() - new Date(a.timestamp).getTime()) < 5 * 60 * 1000
    );

    if (!recentAlert) {
      this.alerts.push(alert);
      
      // Keep only last 100 alerts
      if (this.alerts.length > 100) {
        this.alerts.shift();
      }
    }
  }

  /**
   * Get active alerts
   */
  getActiveAlerts() {
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    return this.alerts.filter(alert => 
      new Date(alert.timestamp).getTime() > fiveMinutesAgo
    );
  }

  /**
   * Clear alerts
   */
  clearAlerts() {
    this.alerts = [];
  }

  /**
   * Get performance report
   */
  async getPerformanceReport() {
    const cpu = this.getHistory('cpu');
    const memory = this.getHistory('memory');
    const disk = this.getHistory('disk');

    const avgCPU = cpu.length > 0 
      ? cpu.reduce((sum, m) => sum + m.usage, 0) / cpu.length 
      : 0;

    const avgMemory = memory.length > 0
      ? memory.reduce((sum, m) => sum + m.usage, 0) / memory.length
      : 0;

    const avgDisk = disk.length > 0
      ? disk.reduce((sum, m) => sum + m.usage, 0) / disk.length
      : 0;

    return {
      period: {
        start: cpu.length > 0 ? new Date(cpu[0].timestamp).toISOString() : null,
        end: cpu.length > 0 ? new Date(cpu[cpu.length - 1].timestamp).toISOString() : null
      },
      averages: {
        cpu: avgCPU.toFixed(2),
        memory: avgMemory.toFixed(2),
        disk: avgDisk.toFixed(2)
      },
      peaks: {
        cpu: cpu.length > 0 ? Math.max(...cpu.map(m => m.usage)) : 0,
        memory: memory.length > 0 ? Math.max(...memory.map(m => m.usage)) : 0,
        disk: disk.length > 0 ? Math.max(...disk.map(m => m.usage)) : 0
      },
      history: {
        cpu,
        memory,
        disk
      }
    };
  }
}

// Singleton instance
module.exports = new SystemMonitor();
