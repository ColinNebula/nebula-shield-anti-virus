/**
 * Real Process Behavior Monitor
 * Monitors running processes for suspicious behavior patterns
 * Integrates with behavior-based-detector.js for ML-based threat detection
 */

const si = require('systeminformation');
const EventEmitter = require('events');
const behaviorDetector = require('./behavior-based-detector');

class RealProcessMonitor extends EventEmitter {
    constructor() {
        super();
        this.isMonitoring = false;
        this.monitorInterval = null;
        this.processHistory = new Map();
        this.suspiciousProcesses = new Set();
        this.stats = {
            processesMonitored: 0,
            suspiciousBehaviors: 0,
            threatsDetected: 0,
            startTime: null
        };
        
        // Configuration
        this.config = {
            monitorInterval: 5000, // Check every 5 seconds
            cpuThreshold: 80, // % - Flag processes using excessive CPU
            memoryThreshold: 500 * 1024 * 1024, // 500 MB
            networkThreshold: 10 * 1024 * 1024, // 10 MB/s
            maxProcessHistory: 1000
        };
        
        // Suspicious process patterns
        this.suspiciousPatterns = {
            // Processes that shouldn't be running from temp directories
            tempExecutables: /\\(temp|tmp|appdata\\local\\temp)\\/i,
            // Known suspicious names
            suspiciousNames: /^(svchost32|csrss32|lsass32|winlogon32|services32)\.exe$/i,
            // Obfuscated names
            randomNames: /^[a-z0-9]{32,}\.exe$/i
        };
    }

    /**
     * Start process monitoring
     */
    async start() {
        if (this.isMonitoring) {
            console.log('⚠️  Process monitor is already running');
            return;
        }

        console.log('👁️  Starting process behavior monitor...');
        this.isMonitoring = true;
        this.stats.startTime = new Date();

        // Start monitoring loop
        this.monitorInterval = setInterval(async () => {
            await this.monitorProcesses();
        }, this.config.monitorInterval);

        // Initial scan
        await this.monitorProcesses();

        console.log('✅ Process behavior monitor started');
        this.emit('started');
    }

    /**
     * Stop process monitoring
     */
    stop() {
        if (!this.isMonitoring) {
            return;
        }

        console.log('🛑 Stopping process behavior monitor...');
        this.isMonitoring = false;

        if (this.monitorInterval) {
            clearInterval(this.monitorInterval);
            this.monitorInterval = null;
        }

        console.log('✅ Process behavior monitor stopped');
        this.emit('stopped');
    }

    /**
     * Monitor all running processes
     */
    async monitorProcesses() {
        try {
            // Get current processes
            const processes = await si.processes();
            
            for (const proc of processes.list) {
                await this.analyzeProcess(proc);
            }

            this.stats.processesMonitored = processes.list.length;

        } catch (error) {
            console.error('Process monitoring error:', error.message);
        }
    }

    /**
     * Analyze individual process for suspicious behavior
     */
    async analyzeProcess(proc) {
        const pid = proc.pid;
        const name = proc.name;
        const path = proc.path || '';

        // Skip system processes and known safe processes
        if (this.isSafeProcess(name, path)) {
            return;
        }

        // Track process history
        const previousData = this.processHistory.get(pid);
        const currentData = {
            pid,
            name,
            path,
            cpu: proc.cpu || 0,
            memory: proc.mem || 0,
            timestamp: Date.now(),
            state: proc.state
        };

        this.processHistory.set(pid, currentData);

        // Clean up old history
        if (this.processHistory.size > this.config.maxProcessHistory) {
            const oldestKeys = Array.from(this.processHistory.keys()).slice(0, 100);
            oldestKeys.forEach(key => this.processHistory.delete(key));
        }

        // Analyze for suspicious patterns
        const suspicionScore = await this.calculateSuspicionScore(proc, previousData);

        if (suspicionScore > 0.6) {
            await this.handleSuspiciousProcess(proc, suspicionScore);
        }
    }

    /**
     * Calculate suspicion score for a process
     */
    async calculateSuspicionScore(proc, previousData) {
        let score = 0;
        const reasons = [];

        // Check 1: Executable location
        if (this.suspiciousPatterns.tempExecutables.test(proc.path || '')) {
            score += 0.4;
            reasons.push('Running from temp directory');
        }

        // Check 2: Process name patterns
        if (this.suspiciousPatterns.suspiciousNames.test(proc.name)) {
            score += 0.5;
            reasons.push('Suspicious process name (impersonating system process)');
        }

        if (this.suspiciousPatterns.randomNames.test(proc.name)) {
            score += 0.3;
            reasons.push('Random/obfuscated name');
        }

        // Check 3: Resource usage anomalies
        if (proc.cpu > this.config.cpuThreshold) {
            score += 0.2;
            reasons.push(`High CPU usage: ${proc.cpu}%`);
        }

        if (proc.mem > this.config.memoryThreshold) {
            score += 0.2;
            reasons.push(`High memory usage: ${Math.round(proc.mem / 1024 / 1024)} MB`);
        }

        // Check 4: Rapid process creation (if we have history)
        if (previousData) {
            const timeDiff = (Date.now() - previousData.timestamp) / 1000; // seconds
            if (timeDiff < 2) {
                score += 0.3;
                reasons.push('Rapid process activity');
            }
        }

        // Check 5: Use behavior-based detector ML analysis
        try {
            const behaviorAnalysis = await behaviorDetector.analyzeProcess({
                pid: proc.pid,
                name: proc.name,
                path: proc.path,
                cpu: proc.cpu,
                memory: proc.mem
            });

            if (behaviorAnalysis && behaviorAnalysis.isSuspicious) {
                score += behaviorAnalysis.suspicionScore * 0.5;
                reasons.push(`ML detection: ${behaviorAnalysis.reason}`);
            }
        } catch (error) {
            // Behavior detector might not be available
        }

        if (score > 0) {
            this.emit('suspicionDetected', {
                process: proc,
                score,
                reasons,
                timestamp: new Date().toISOString()
            });
        }

        return Math.min(score, 1.0);
    }

    /**
     * Handle suspicious process
     */
    async handleSuspiciousProcess(proc, score) {
        const pid = proc.pid;
        
        if (this.suspiciousProcesses.has(pid)) {
            return; // Already flagged
        }

        this.suspiciousProcesses.add(pid);
        this.stats.suspiciousBehaviors++;

        console.log(`⚠️  SUSPICIOUS PROCESS DETECTED:`);
        console.log(`   PID: ${pid}`);
        console.log(`   Name: ${proc.name}`);
        console.log(`   Path: ${proc.path || 'unknown'}`);
        console.log(`   Suspicion Score: ${(score * 100).toFixed(1)}%`);

        // Emit event for UI notification
        this.emit('suspiciousProcess', {
            pid,
            name: proc.name,
            path: proc.path,
            score,
            cpu: proc.cpu,
            memory: proc.mem,
            timestamp: new Date().toISOString()
        });

        // If score is very high, consider it a threat
        if (score > 0.85) {
            this.stats.threatsDetected++;
            this.emit('threatDetected', {
                type: 'suspicious_process',
                pid,
                name: proc.name,
                path: proc.path,
                score,
                severity: 'high',
                timestamp: new Date().toISOString()
            });

            // Optional: Auto-kill highly suspicious processes
            // Commented out for safety - should be user decision
            // await this.terminateProcess(pid);
        }
    }

    /**
     * Check if process is known to be safe
     */
    isSafeProcess(name, path) {
        const safePaths = [
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\Program Files',
            'C:\\Program Files (x86)'
        ];

        const safeProcesses = [
            'System',
            'Registry',
            'smss.exe',
            'csrss.exe',
            'wininit.exe',
            'services.exe',
            'lsass.exe',
            'svchost.exe',
            'explorer.exe'
        ];

        // Check if process name is in safe list
        if (safeProcesses.includes(name)) {
            // But verify it's in a safe path
            return safePaths.some(safePath => path.startsWith(safePath));
        }

        return false;
    }

    /**
     * Terminate a process (with user confirmation in production)
     */
    async terminateProcess(pid) {
        try {
            if (process.platform === 'win32') {
                const { exec } = require('child_process');
                const util = require('util');
                const execAsync = util.promisify(exec);
                
                await execAsync(`taskkill /PID ${pid} /F`);
                console.log(`   🔪 Terminated process: PID ${pid}`);
                
                this.suspiciousProcesses.delete(pid);
                this.emit('processTerminated', { pid });
                
                return true;
            }
        } catch (error) {
            console.error(`Failed to terminate process ${pid}:`, error.message);
            return false;
        }
    }

    /**
     * Get suspicious processes list
     */
    getSuspiciousProcesses() {
        const suspicious = [];
        for (const pid of this.suspiciousProcesses) {
            const data = this.processHistory.get(pid);
            if (data) {
                suspicious.push(data);
            }
        }
        return suspicious;
    }

    /**
     * Clear process from suspicious list
     */
    clearSuspiciousProcess(pid) {
        this.suspiciousProcesses.delete(pid);
        console.log(`Cleared suspicious flag for PID ${pid}`);
    }

    /**
     * Get monitoring statistics
     */
    getStats() {
        const uptime = this.stats.startTime 
            ? Math.floor((Date.now() - this.stats.startTime.getTime()) / 1000)
            : 0;

        return {
            ...this.stats,
            uptime,
            isMonitoring: this.isMonitoring,
            suspiciousProcessCount: this.suspiciousProcesses.size,
            trackedProcesses: this.processHistory.size
        };
    }

    /**
     * Update configuration
     */
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
        
        // Restart monitoring with new config
        if (this.isMonitoring) {
            this.stop();
            this.start();
        }
        
        console.log('Process monitor configuration updated');
    }
}

// Export singleton instance
module.exports = new RealProcessMonitor();
