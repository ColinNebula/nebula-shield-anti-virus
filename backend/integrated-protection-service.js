/**
 * Integrated Protection Service
 * Starts all real-time protection components
 */

const realFileMonitor = require('./real-time-file-monitor');
const realProcessMonitor = require('./real-process-monitor');
const cloudThreatIntel = require('./cloud-threat-intelligence-manager');
const realFileScanner = require('./real-file-scanner');

class IntegratedProtection {
    constructor() {
        this.isRunning = false;
        this.stats = {
            startTime: null,
            totalThreats: 0,
            filesScanned: 0,
            processesMonitored: 0
        };

        // Set up event handlers
        this.setupEventHandlers();
    }

    /**
     * Set up event handlers for all monitoring services
     */
    setupEventHandlers() {
        // File monitor events
        realFileMonitor.on('threatDetected', async (event) => {
            this.stats.totalThreats++;
            console.log(`\n🚨 FILE THREAT DETECTED: ${event.filePath}`);
            
            // Check with cloud threat intelligence
            if (event.threat.file_hash) {
                try {
                    const cloudCheck = await cloudThreatIntel.checkFileHash(event.threat.file_hash);
                    if (cloudCheck.isThreat) {
                        console.log(`   ✓ Confirmed by ${cloudCheck.source}: ${cloudCheck.detectionRatio}`);
                    }
                } catch (error) {
                    // Cloud check failed, continue with local detection
                }
            }
        });

        realFileMonitor.on('fileScanComplete', (event) => {
            this.stats.filesScanned++;
        });

        // Process monitor events
        realProcessMonitor.on('suspiciousProcess', (event) => {
            console.log(`\n⚠️  SUSPICIOUS PROCESS: ${event.name} (PID: ${event.pid})`);
            console.log(`   Score: ${(event.score * 100).toFixed(1)}%`);
        });

        realProcessMonitor.on('threatDetected', (event) => {
            this.stats.totalThreats++;
            console.log(`\n🚨 PROCESS THREAT: ${event.name} (PID: ${event.pid})`);
        });
    }

    /**
     * Start all protection services
     */
    async start() {
        if (this.isRunning) {
            console.log('⚠️  Integrated protection is already running');
            return;
        }

        console.log('\n╔═══════════════════════════════════════════════════════════╗');
        console.log('║      Nebula Shield - Integrated Protection System        ║');
        console.log('╚═══════════════════════════════════════════════════════════╝\n');

        this.isRunning = true;
        this.stats.startTime = new Date();

        try {
            // Start real-time file monitoring
            console.log('🔍 Activating real-time file monitoring...');
            await realFileMonitor.start();

            // Start process behavior monitoring
            console.log('👁️  Activating process behavior monitoring...');
            await realProcessMonitor.start();

            console.log('\n✅ All protection services activated!\n');
            console.log('📊 Protection Status:');
            console.log(`   • File Monitor: ✅ Active`);
            console.log(`   • Process Monitor: ✅ Active`);
            console.log(`   • Cloud Intelligence: ${this.getCloudIntelStatus()}`);
            console.log('\n');

        } catch (error) {
            console.error('❌ Failed to start protection services:', error);
            this.isRunning = false;
            throw error;
        }
    }

    /**
     * Stop all protection services
     */
    async stop() {
        if (!this.isRunning) {
            return;
        }

        console.log('\n🛑 Stopping integrated protection...');

        await realFileMonitor.stop();
        await realProcessMonitor.stop();

        this.isRunning = false;
        console.log('✅ All protection services stopped\n');
    }

    /**
     * Get cloud intelligence status
     */
    getCloudIntelStatus() {
        const status = cloudThreatIntel.getStatus();
        const available = Object.values(status.apis).filter(s => s === 'available').length;
        const total = Object.keys(status.apis).length;
        
        if (available === 0) {
            return '⚠️  Using local detection only';
        } else if (available < total) {
            return `🟡 Partial (${available}/${total} APIs)`;
        } else {
            return `✅ Full (${available}/${total} APIs)`;
        }
    }

    /**
     * Get comprehensive statistics
     */
    getStats() {
        const fileStats = realFileMonitor.getStats();
        const processStats = realProcessMonitor.getStats();
        const cloudStats = cloudThreatIntel.getStatus();

        const uptime = this.stats.startTime 
            ? Math.floor((Date.now() - this.stats.startTime.getTime()) / 1000)
            : 0;

        return {
            isRunning: this.isRunning,
            uptime,
            totalThreats: fileStats.threatsDetected + processStats.threatsDetected,
            fileMonitor: {
                filesScanned: fileStats.filesScanned,
                threatsDetected: fileStats.threatsDetected,
                threatsBlocked: fileStats.threatsBlocked,
                queueSize: fileStats.queueSize
            },
            processMonitor: {
                processesMonitored: processStats.processesMonitored,
                suspiciousBehaviors: processStats.suspiciousBehaviors,
                threatsDetected: processStats.threatsDetected,
                suspiciousProcessCount: processStats.suspiciousProcessCount
            },
            cloudIntelligence: {
                apis: cloudStats.apis,
                cacheSize: cloudStats.cacheSize
            }
        };
    }

    /**
     * Scan specific file on demand
     */
    async scanFile(filePath) {
        try {
            const result = await realFileScanner.scanFile(filePath);
            
            // Check with cloud intelligence if suspicious
            if (result.threat_type !== 'CLEAN' && result.file_hash) {
                const cloudCheck = await cloudThreatIntel.checkFileHash(result.file_hash);
                result.cloudVerification = cloudCheck;
            }

            return result;
        } catch (error) {
            throw error;
        }
    }

    /**
     * Check IP address reputation
     */
    async checkIP(ipAddress) {
        return await cloudThreatIntel.checkIPReputation(ipAddress);
    }

    /**
     * Check URL safety
     */
    async checkURL(url) {
        return await cloudThreatIntel.checkURL(url);
    }
}

// Export singleton instance
module.exports = new IntegratedProtection();

// Auto-start if run directly
if (require.main === module) {
    const protection = module.exports;
    
    protection.start().catch(error => {
        console.error('Failed to start protection:', error);
        process.exit(1);
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
        console.log('\n\nReceived SIGINT, shutting down gracefully...');
        await protection.stop();
        process.exit(0);
    });

    process.on('SIGTERM', async () => {
        console.log('\n\nReceived SIGTERM, shutting down gracefully...');
        await protection.stop();
        process.exit(0);
    });

    // Keep process alive
    setInterval(() => {
        const stats = protection.getStats();
        console.log(`\n📊 Protection Stats (Uptime: ${Math.floor(stats.uptime / 60)}m ${stats.uptime % 60}s)`);
        console.log(`   Files Scanned: ${stats.fileMonitor.filesScanned}`);
        console.log(`   Processes Monitored: ${stats.processMonitor.processesMonitored}`);
        console.log(`   Threats Detected: ${stats.totalThreats}`);
        console.log(`   Queue Size: ${stats.fileMonitor.queueSize}`);
    }, 30000); // Every 30 seconds
}
