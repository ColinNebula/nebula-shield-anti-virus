/**
 * Real-Time File Monitor
 * Watches file system for changes and automatically scans new/modified files
 * Provides real-time protection against malware
 */

const chokidar = require('chokidar');
const path = require('path');
const os = require('os');
const EventEmitter = require('events');
const realFileScanner = require('./real-file-scanner');

class RealTimeFileMonitor extends EventEmitter {
    constructor() {
        super();
        this.watchers = new Map();
        this.isMonitoring = false;
        this.scanQueue = [];
        this.isProcessingQueue = false;
        this.stats = {
            filesMonitored: 0,
            filesScanned: 0,
            threatsDetected: 0,
            threatsBlocked: 0,
            startTime: null
        };
        
        // Directories to monitor (high-risk locations)
        this.monitoredPaths = [
            path.join(os.homedir(), 'Downloads'),
            path.join(os.homedir(), 'AppData', 'Local', 'Temp'),
            path.join(os.tmpdir()),
            'C:\\Windows\\Temp'
        ];
        
        // File extensions to monitor (executable and risky files)
        this.monitoredExtensions = [
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.jar', '.msi', '.com', '.pif', '.app', '.deb', '.rpm',
            '.sh', '.py', '.rb', '.pl', '.php', '.asp', '.aspx'
        ];
        
        // Debouncing map to avoid scanning same file multiple times
        this.recentScans = new Map();
        this.debounceTime = 3000; // 3 seconds
        
        // Configuration
        this.config = {
            autoQuarantine: true,
            scanOnCreate: true,
            scanOnModify: true,
            maxFileSize: 100 * 1024 * 1024, // 100 MB
            ignorePatterns: [
                '**/node_modules/**',
                '**/.git/**',
                '**/System Volume Information/**',
                '**/$RECYCLE.BIN/**'
            ]
        };
    }

    /**
     * Start real-time file monitoring
     */
    async start() {
        if (this.isMonitoring) {
            console.log('⚠️  File monitor is already running');
            return;
        }

        console.log('🔍 Starting real-time file monitor...');
        this.isMonitoring = true;
        this.stats.startTime = new Date();

        // Start monitoring each path
        for (const monitorPath of this.monitoredPaths) {
            try {
                await this.watchDirectory(monitorPath);
            } catch (error) {
                console.error(`Failed to watch ${monitorPath}:`, error.message);
            }
        }

        // Start scan queue processor
        this.startQueueProcessor();

        console.log('✅ Real-time file monitor started');
        console.log(`   Watching ${this.watchers.size} directories`);
        this.emit('started');
    }

    /**
     * Stop file monitoring
     */
    async stop() {
        if (!this.isMonitoring) {
            return;
        }

        console.log('🛑 Stopping real-time file monitor...');
        this.isMonitoring = false;

        // Close all watchers
        for (const [path, watcher] of this.watchers) {
            await watcher.close();
            console.log(`   Stopped watching: ${path}`);
        }
        this.watchers.clear();

        console.log('✅ Real-time file monitor stopped');
        this.emit('stopped');
    }

    /**
     * Watch a specific directory
     */
    async watchDirectory(dirPath) {
        if (this.watchers.has(dirPath)) {
            console.log(`Already watching: ${dirPath}`);
            return;
        }

        const watcher = chokidar.watch(dirPath, {
            ignored: this.config.ignorePatterns,
            persistent: true,
            ignoreInitial: true, // Don't scan existing files on startup
            awaitWriteFinish: {
                stabilityThreshold: 2000,
                pollInterval: 100
            },
            depth: 5 // Limit recursion depth for performance
        });

        watcher
            .on('add', (filePath) => this.onFileCreated(filePath))
            .on('change', (filePath) => this.onFileModified(filePath))
            .on('error', (error) => console.error(`Watcher error on ${dirPath}:`, error))
            .on('ready', () => {
                console.log(`   ✓ Watching: ${dirPath}`);
                this.stats.filesMonitored++;
            });

        this.watchers.set(dirPath, watcher);
    }

    /**
     * Handle file creation event
     */
    onFileCreated(filePath) {
        if (!this.config.scanOnCreate || !this.shouldScanFile(filePath)) {
            return;
        }

        console.log(`📄 New file detected: ${filePath}`);
        this.queueFileForScan(filePath, 'created');
        this.emit('fileCreated', { filePath });
    }

    /**
     * Handle file modification event
     */
    onFileModified(filePath) {
        if (!this.config.scanOnModify || !this.shouldScanFile(filePath)) {
            return;
        }

        console.log(`📝 File modified: ${filePath}`);
        this.queueFileForScan(filePath, 'modified');
        this.emit('fileModified', { filePath });
    }

    /**
     * Check if file should be scanned
     */
    shouldScanFile(filePath) {
        // Check file extension
        const ext = path.extname(filePath).toLowerCase();
        if (!this.monitoredExtensions.includes(ext)) {
            return false;
        }

        // Check if recently scanned (debouncing)
        const lastScan = this.recentScans.get(filePath);
        if (lastScan && (Date.now() - lastScan < this.debounceTime)) {
            return false;
        }

        // Check file size (avoid scanning huge files)
        try {
            const fs = require('fs');
            const stats = fs.statSync(filePath);
            if (stats.size > this.config.maxFileSize) {
                console.log(`⚠️  File too large to scan: ${filePath} (${stats.size} bytes)`);
                return false;
            }
        } catch (error) {
            // File might not exist or inaccessible
            return false;
        }

        return true;
    }

    /**
     * Add file to scan queue
     */
    queueFileForScan(filePath, eventType) {
        // Avoid duplicates
        const exists = this.scanQueue.some(item => item.filePath === filePath);
        if (exists) {
            return;
        }

        this.scanQueue.push({
            filePath,
            eventType,
            timestamp: Date.now()
        });

        // Update recent scans
        this.recentScans.set(filePath, Date.now());

        // Clean up old entries
        if (this.recentScans.size > 1000) {
            const now = Date.now();
            for (const [path, time] of this.recentScans.entries()) {
                if (now - time > this.debounceTime * 2) {
                    this.recentScans.delete(path);
                }
            }
        }

        console.log(`   📋 Queued for scan: ${filePath} (queue size: ${this.scanQueue.length})`);
    }

    /**
     * Process scan queue
     */
    async startQueueProcessor() {
        this.isProcessingQueue = true;

        while (this.isMonitoring) {
            if (this.scanQueue.length === 0) {
                // Wait a bit before checking again
                await new Promise(resolve => setTimeout(resolve, 1000));
                continue;
            }

            const item = this.scanQueue.shift();
            await this.scanFile(item);

            // Small delay between scans to avoid CPU overload
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        this.isProcessingQueue = false;
    }

    /**
     * Scan a file for threats
     */
    async scanFile(item) {
        const { filePath, eventType } = item;

        try {
            console.log(`🔬 Scanning: ${filePath}`);
            this.stats.filesScanned++;

            // Use real file scanner
            const result = await realFileScanner.scanFile(filePath);

            if (result.threat_type !== 'CLEAN') {
                // THREAT DETECTED!
                console.log(`🚨 THREAT DETECTED: ${filePath}`);
                console.log(`   Type: ${result.threat_type}`);
                console.log(`   Name: ${result.threat_name}`);
                
                this.stats.threatsDetected++;

                // Auto-quarantine if enabled
                if (this.config.autoQuarantine) {
                    await this.quarantineFile(filePath, result);
                }

                // Emit threat event
                this.emit('threatDetected', {
                    filePath,
                    eventType,
                    threat: result,
                    timestamp: new Date().toISOString()
                });
            } else {
                console.log(`   ✓ Clean: ${filePath}`);
                this.emit('fileScanComplete', {
                    filePath,
                    result,
                    timestamp: new Date().toISOString()
                });
            }

        } catch (error) {
            console.error(`❌ Scan error for ${filePath}:`, error.message);
            this.emit('scanError', {
                filePath,
                error: error.message
            });
        }
    }

    /**
     * Quarantine malicious file
     */
    async quarantineFile(filePath, threatInfo) {
        try {
            const fs = require('fs').promises;
            const quarantineDir = path.join(__dirname, 'quarantine_vault');
            
            // Ensure quarantine directory exists
            await fs.mkdir(quarantineDir, { recursive: true });

            // Generate unique quarantine filename
            const timestamp = Date.now();
            const fileName = path.basename(filePath);
            const quarantinePath = path.join(quarantineDir, `${timestamp}_${fileName}`);

            // Move file to quarantine
            await fs.rename(filePath, quarantinePath);

            // Save metadata
            const metadataPath = quarantinePath + '.json';
            const metadata = {
                originalPath: filePath,
                quarantinePath,
                threatType: threatInfo.threat_type,
                threatName: threatInfo.threat_name,
                quarantineDate: new Date().toISOString(),
                fileHash: threatInfo.file_hash,
                fileSize: threatInfo.file_size
            };
            await fs.writeFile(metadataPath, JSON.stringify(metadata, null, 2));

            this.stats.threatsBlocked++;
            console.log(`   🔒 Quarantined: ${quarantinePath}`);

            this.emit('fileQuarantined', {
                originalPath: filePath,
                quarantinePath,
                metadata
            });

            return true;
        } catch (error) {
            console.error(`Failed to quarantine ${filePath}:`, error.message);
            return false;
        }
    }

    /**
     * Add custom directory to watch
     */
    async addWatchPath(dirPath) {
        if (!this.monitoredPaths.includes(dirPath)) {
            this.monitoredPaths.push(dirPath);
            if (this.isMonitoring) {
                await this.watchDirectory(dirPath);
            }
            console.log(`Added watch path: ${dirPath}`);
        }
    }

    /**
     * Remove directory from watch
     */
    async removeWatchPath(dirPath) {
        const index = this.monitoredPaths.indexOf(dirPath);
        if (index > -1) {
            this.monitoredPaths.splice(index, 1);
            
            if (this.watchers.has(dirPath)) {
                await this.watchers.get(dirPath).close();
                this.watchers.delete(dirPath);
                console.log(`Removed watch path: ${dirPath}`);
            }
        }
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
            queueSize: this.scanQueue.length,
            watchedPaths: Array.from(this.watchers.keys())
        };
    }

    /**
     * Update configuration
     */
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
        console.log('Configuration updated:', this.config);
    }
}

// Export singleton instance
module.exports = new RealTimeFileMonitor();
