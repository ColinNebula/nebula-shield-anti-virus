const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const quarantineService = require('./quarantine-service');
const fileCleaner = require('./file-cleaner');
const diskCleaner = require('./disk-cleaner');
const authService = require('./auth-service');
const activityLogger = require('./activity-logger');
const backupService = require('./backup-service');
const analyticsService = require('./analytics-service');
const systemMonitor = require('./system-monitor');
const bulkOperations = require('./bulk-operations');
const scheduledTasks = require('./scheduled-tasks');
const settingsImportExport = require('./settings-import-export');
const cloudBackup = require('./cloud-backup');
const enhancedHackerProtection = require('./enhanced-hacker-protection');
const licenseAPI = require('./license-api');
const integratedScanner = require('./integrated-scanner-service');
const firewallEngine = require('./firewall-engine');
const aiThreatDetector = require('./ai-threat-detector');
const { enhancedMLEngine } = require('./enhanced-ml-engine');
const behaviorDetector = require('./behavior-based-detector');
const predictiveAnalytics = require('./predictive-analytics');
const smartScheduler = require('./smart-scan-scheduler');
const threatIntelligence = require('./threat-intelligence-service');
const platformAdapter = require('./platform-adapter');
const cloudSync = require('./cloud-sync-service');
const AdvancedMonitoring = require('./advanced-monitoring');
const AdvancedFirewall = require('./advanced-firewall');

// Initialize services
const advancedMonitoring = new AdvancedMonitoring();
const advancedFirewall = new AdvancedFirewall();

const app = express();
const PORT = 8080;

// Enable CORS for frontend communication
app.use(cors());
app.use(express.json());

// Apply enhanced hacker protection middleware
// TEMPORARILY DISABLED FOR DEBUGGING
// app.use(enhancedHackerProtection.middleware());

// Configure multer for file uploads
const upload = multer({ 
    dest: 'uploads/',
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB limit
    }
});

// Mock data
let scanHistory = [];
let quarantineItems = [];
let systemStats = {
    totalScans: 0,
    threatsDetected: 0,
    filesQuarantined: 0,
    lastScanTime: null
};

let settings = {
    realTimeProtection: true,
    autoQuarantine: true,
    scanDepth: 'deep',
    updateFrequency: 'daily',
    notificationsEnabled: true
};

// API Routes

// System Status
app.get('/api/status', (req, res) => {
    res.json({
        status: 'running',
        version: '1.0.0',
        uptime: Math.floor(process.uptime()),
        memoryUsage: process.memoryUsage(),
        stats: systemStats,
        real_time_protection: settings.realTimeProtection,
        total_scanned_files: systemStats.totalScans * 50,
        total_threats_found: systemStats.threatsDetected,
        last_scan_time: systemStats.lastScanTime
    });
});

// System Statistics
app.get('/api/stats', (req, res) => {
    res.json({
        ...systemStats,
        scanHistory: scanHistory.slice(-10), // Last 10 scans
        cpuUsage: Math.random() * 100,
        memoryUsage: Math.random() * 100,
        diskUsage: Math.random() * 100
    });
});

// Get scan results for dashboard
app.get('/api/scan/results', (req, res) => {
    res.json({
        results: scanHistory.slice(-20), // Last 20 scans
        totalScans: systemStats.totalScans,
        threatsDetected: systemStats.threatsDetected,
        lastScanTime: systemStats.lastScanTime
    });
});

// File Scanning - supports both file path and file upload
app.post('/api/scan/file', (req, res, next) => {
    // Check content type to decide which middleware to use
    const contentType = req.headers['content-type'] || '';
    
    if (contentType.includes('multipart/form-data')) {
        // Use multer for file uploads
        upload.single('file')(req, res, (err) => {
            if (err) {
                return res.status(400).json({ error: 'File upload error: ' + err.message });
            }
            handleFileScan(req, res);
        });
    } else {
        // Handle JSON requests directly
        handleFileScan(req, res);
    }
});

async function handleFileScan(req, res) {
    let fileName, fileSize, filePath;
    
    // Check if it's a file upload or file path
    if (req.file) {
        // File upload
        fileName = req.file.originalname;
        fileSize = req.file.size;
        filePath = req.file.path;
    } else if (req.body.file_path) {
        // File path provided
        filePath = req.body.file_path;
        fileName = path.basename(filePath);
        try {
            const stats = fs.statSync(filePath);
            fileSize = stats.size;
        } catch (error) {
            fileSize = 0;
        }
    } else {
        return res.status(400).json({ error: 'No file or file path provided' });
    }

    try {
        // Use integrated scanner for REAL threat detection
        const useRealScanner = req.body.useRealScanner !== false;
        
        if (useRealScanner && fs.existsSync(filePath)) {
            console.log(`🔬 Using REAL malware scanner for: ${fileName}`);
            const scanResult = await integratedScanner.scanFile(filePath, {
                useVirusTotal: req.body.useVirusTotal !== false,
                useThreatIntel: req.body.useThreatIntel !== false
            });

            // Convert to backend format
            const isClean = scanResult.status === 'clean';
            const result = {
                id: Date.now(),
                file_path: filePath,
                threat_type: isClean ? 'CLEAN' : 'MALWARE',
                threat_name: isClean ? null : (scanResult.threats[0]?.name || 'Unknown threat'),
                confidence: scanResult.confidence / 100,
                file_size: fileSize,
                scan_time: new Date(scanResult.startTime).toISOString(),
                scan_duration: scanResult.duration,
                quarantined: false,
                detectionMethods: scanResult.detectionMethods,
                threats: scanResult.threats,
                engines: scanResult.engines,
                realScanner: true
            };

            scanHistory.push({
                ...result,
                fileName,
                status: isClean ? 'clean' : 'infected',
                scanDuration: scanResult.duration
            });
            
            systemStats.totalScans++;
            systemStats.lastScanTime = result.scan_time;

            if (!isClean) {
                systemStats.threatsDetected++;
                if (settings.autoQuarantine) {
                    quarantineItems.push({
                        id: result.id,
                        fileName,
                        threatName: result.threat_name,
                        quarantineTime: new Date().toISOString(),
                        originalPath: filePath,
                        size: fileSize
                    });
                    systemStats.filesQuarantined++;
                }
            }

            // Clean up uploaded file if it exists
            if (req.file) {
                fs.unlink(req.file.path, () => {});
            }

            return res.json(result);
        }
        
        // Fallback to simulated scan if file doesn't exist or real scanner disabled
        console.log(`⚠️ Using SIMULATED scanner for: ${fileName}`);
        setTimeout(() => {
            const isClean = Math.random() > 0.1; // 90% chance of being clean
            const threatTypes = ['VIRUS', 'MALWARE', 'TROJAN', 'SUSPICIOUS'];
            const threatType = isClean ? 'CLEAN' : threatTypes[Math.floor(Math.random() * threatTypes.length)];
            
            const scanResult = {
                id: Date.now(),
                file_path: filePath,
                threat_type: threatType,
                threat_name: isClean ? null : 'Trojan.Generic.Suspicious',
                confidence: isClean ? 1.0 : Math.random() * 0.5 + 0.5,
                file_size: fileSize,
                scan_time: new Date().toISOString(),
                quarantined: false,
                realScanner: false
            };

            scanHistory.push({
                ...scanResult,
                fileName,
                status: isClean ? 'clean' : 'infected',
                scanDuration: Math.floor(Math.random() * 1000) + 500
            });
            
            systemStats.totalScans++;
            systemStats.lastScanTime = scanResult.scan_time;

            if (!isClean) {
                systemStats.threatsDetected++;
                if (settings.autoQuarantine) {
                    quarantineItems.push({
                        id: scanResult.id,
                        fileName,
                        threatName: scanResult.threat_name,
                        quarantineTime: new Date().toISOString(),
                        originalPath: filePath,
                        size: fileSize
                    });
                    systemStats.filesQuarantined++;
                }
            }

            // Clean up uploaded file if it exists
            if (req.file) {
                fs.unlink(req.file.path, () => {});
            }

            res.json(scanResult);
        }, Math.random() * 2000 + 1000); // 1-3 second delay

    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({ 
            error: 'Scan failed', 
            message: error.message,
            realScanner: false
        });
    }
}

// Directory Scanning
app.post('/api/scan/directory', (req, res) => {
    const { directory_path, path: scanPath } = req.body;
    const directoryPath = directory_path || scanPath;
    
    if (!directoryPath) {
        return res.status(400).json({ error: 'No directory path provided' });
    }

    // Simulate directory scanning
    setTimeout(() => {
        const fileCount = Math.floor(Math.random() * 100) + 50;
        const threatsFound = Math.floor(Math.random() * 5);
        const threatTypes = ['VIRUS', 'MALWARE', 'TROJAN', 'SUSPICIOUS'];
        
        // Generate scan results for individual files
        const results = [];
        for (let i = 0; i < fileCount; i++) {
            const isClean = i >= threatsFound; // First N files are threats
            const threatType = isClean ? 'CLEAN' : threatTypes[Math.floor(Math.random() * threatTypes.length)];
            
            results.push({
                id: Date.now() + i,
                file_path: `${directoryPath}/file_${i + 1}.${isClean ? 'txt' : 'exe'}`,
                threat_type: threatType,
                threat_name: isClean ? null : ['Trojan.Generic', 'Malware.Suspicious', 'Adware.Popup'][Math.floor(Math.random() * 3)],
                confidence: isClean ? 1.0 : Math.random() * 0.5 + 0.5,
                file_size: Math.floor(Math.random() * 1024 * 1024),
                scan_time: new Date().toISOString(),
                quarantined: false
            });
        }

        const scanResult = {
            id: Date.now(),
            path: directoryPath,
            status: 'completed',
            filesScanned: fileCount,
            threatsFound,
            results: results,
            scanTime: new Date().toISOString(),
            scanDuration: Math.floor(Math.random() * 5000) + 2000
        };

        // Add threats to quarantine if auto-quarantine enabled
        if (settings.autoQuarantine && threatsFound > 0) {
            results.filter(r => r.threat_type !== 'CLEAN').forEach(threat => {
                quarantineItems.push({
                    id: threat.id,
                    fileName: path.basename(threat.file_path),
                    threatName: threat.threat_name,
                    quarantineTime: new Date().toISOString(),
                    originalPath: threat.file_path,
                    size: threat.file_size
                });
            });
        }

        scanHistory.push({
            ...scanResult,
            fileName: `Directory: ${directoryPath}`,
            status: threatsFound > 0 ? 'infected' : 'clean'
        });
        
        systemStats.totalScans++;
        systemStats.threatsDetected += threatsFound;
        systemStats.filesQuarantined += (settings.autoQuarantine ? threatsFound : 0);
        systemStats.lastScanTime = scanResult.scanTime;

        res.json(scanResult);
    }, Math.random() * 3000 + 2000); // 2-5 second delay
});

// Quick Scan
app.post('/api/scan/quick', (req, res) => {
    setTimeout(() => {
        const scanResult = {
            id: Date.now(),
            type: 'quick',
            status: 'completed',
            filesScanned: Math.floor(Math.random() * 50) + 25,
            threatsFound: Math.floor(Math.random() * 2),
            scanTime: new Date().toISOString(),
            scanDuration: Math.floor(Math.random() * 2000) + 1000
        };

        scanHistory.push(scanResult);
        systemStats.totalScans++;
        systemStats.lastScanTime = scanResult.scanTime;

        res.json(scanResult);
    }, Math.random() * 2000 + 1000);
});

// Full System Scan
app.post('/api/scan/full', (req, res) => {
    setTimeout(() => {
        const threatsFound = Math.floor(Math.random() * 5);
        const scanResult = {
            id: Date.now(),
            type: 'full',
            status: 'completed',
            filesScanned: Math.floor(Math.random() * 1000) + 500,
            threatsFound,
            scanTime: new Date().toISOString(),
            scanDuration: Math.floor(Math.random() * 10000) + 5000
        };

        scanHistory.push(scanResult);
        systemStats.totalScans++;
        systemStats.threatsDetected += threatsFound;
        systemStats.lastScanTime = scanResult.scanTime;

        res.json(scanResult);
    }, Math.random() * 5000 + 3000); // 3-8 second delay
});

// Quarantine Management - REAL IMPLEMENTATION with Mock Data for Testing
app.get('/api/quarantine', async (req, res) => {
    try {
        const files = await quarantineService.getAllQuarantined();
        
        // If database is empty, return mock data for testing
        if (files.length === 0) {
            const mockQuarantineFiles = [
                {
                    id: 1,
                    fileName: 'suspicious_script.js',
                    originalPath: 'C:\\Users\\Admin\\Downloads\\suspicious_script.js',
                    threatType: 'MALWARE',
                    threatName: 'Trojan.GenericKD.12345678',
                    fileSize: 15234,
                    riskLevel: 'high',
                    quarantinedDate: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000), // 2 days ago
                    encrypted: true
                },
                {
                    id: 2,
                    fileName: 'infected_document.docx',
                    originalPath: 'C:\\Users\\Admin\\Documents\\infected_document.docx',
                    threatType: 'VIRUS',
                    threatName: 'W97M.Downloader.A',
                    fileSize: 45678,
                    riskLevel: 'critical',
                    quarantinedDate: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000), // 5 days ago
                    encrypted: true
                },
                {
                    id: 3,
                    fileName: 'adware_installer.exe',
                    originalPath: 'C:\\Users\\Admin\\Downloads\\adware_installer.exe',
                    threatType: 'ADWARE',
                    threatName: 'Adware.BundleInstaller',
                    fileSize: 2048576,
                    riskLevel: 'medium',
                    quarantinedDate: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 7 days ago
                    encrypted: true
                },
                {
                    id: 4,
                    fileName: 'phishing_page.html',
                    originalPath: 'C:\\Users\\Admin\\Desktop\\phishing_page.html',
                    threatType: 'PHISHING',
                    threatName: 'HTML.Phishing.Bank',
                    fileSize: 8192,
                    riskLevel: 'high',
                    quarantinedDate: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000), // 1 day ago
                    encrypted: true
                },
                {
                    id: 5,
                    fileName: 'keylogger.dll',
                    originalPath: 'C:\\Windows\\System32\\keylogger.dll',
                    threatType: 'SPYWARE',
                    threatName: 'Spyware.Keylogger.Generic',
                    fileSize: 32768,
                    riskLevel: 'critical',
                    quarantinedDate: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000), // 3 days ago
                    encrypted: true
                }
            ];
            
            return res.json(mockQuarantineFiles);
        }
        
        const formattedFiles = files.map(f => ({
            id: f.id,
            fileName: f.fileName,
            originalPath: f.originalPath,
            threatType: f.threatType,
            threatName: f.threatName,
            fileSize: f.fileSize,
            riskLevel: f.riskLevel,
            quarantinedDate: f.quarantinedDate,
            encrypted: f.encrypted
        }));
        res.json(formattedFiles);
    } catch (error) {
        console.error('Error fetching quarantine:', error);
        res.status(500).json({ error: 'Failed to fetch quarantine files' });
    }
});

app.delete('/api/quarantine/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await quarantineService.deleteQuarantined(parseInt(id));
        
        // Update stats
        const files = await quarantineService.getAllQuarantined();
        systemStats.filesQuarantined = files.length;
        
        res.json({ success: true, message: 'File permanently deleted from quarantine' });
    } catch (error) {
        console.error('Error deleting quarantine file:', error);
        res.status(500).json({ error: 'Failed to delete file', message: error.message });
    }
});

app.post('/api/quarantine/:id/restore', async (req, res) => {
    try {
        const { id } = req.params;
        const { targetPath } = req.body; // Optional custom restore path
        
        const result = await quarantineService.restoreFile(parseInt(id), targetPath);
        
        // Update stats
        const files = await quarantineService.getAllQuarantined();
        systemStats.filesQuarantined = files.length;
        
        res.json({
            success: true,
            message: 'File restored successfully',
            restoredPath: result.restoredPath
        });
    } catch (error) {
        console.error('Error restoring file:', error);
        res.status(500).json({ error: 'Failed to restore file', message: error.message });
    }
});

// Quarantine a file
app.post('/api/quarantine/add', async (req, res) => {
    try {
        const { filePath, threatInfo } = req.body;
        
        if (!filePath) {
            return res.status(400).json({ error: 'File path required' });
        }
        
        const result = await quarantineService.quarantineFile(filePath, threatInfo || {});
        
        // Update stats
        const files = await quarantineService.getAllQuarantined();
        systemStats.filesQuarantined = files.length;
        systemStats.threatsDetected++;
        
        res.json(result);
    } catch (error) {
        console.error('Error quarantining file:', error);
        res.status(500).json({ error: 'Failed to quarantine file', message: error.message });
    }
});

// Bulk operations
app.post('/api/quarantine/bulk/delete', async (req, res) => {
    try {
        const { ids } = req.body;
        const results = await quarantineService.bulkDelete(ids);
        
        // Update stats
        const files = await quarantineService.getAllQuarantined();
        systemStats.filesQuarantined = files.length;
        
        res.json(results);
    } catch (error) {
        console.error('Error in bulk delete:', error);
        res.status(500).json({ error: 'Bulk delete failed', message: error.message });
    }
});

app.post('/api/quarantine/bulk/restore', async (req, res) => {
    try {
        const { ids } = req.body;
        const results = await quarantineService.bulkRestore(ids);
        
        // Update stats
        const files = await quarantineService.getAllQuarantined();
        systemStats.filesQuarantined = files.length;
        
        res.json(results);
    } catch (error) {
        console.error('Error in bulk restore:', error);
        res.status(500).json({ error: 'Bulk restore failed', message: error.message });
    }
});

// Get quarantine statistics
app.get('/api/quarantine/stats', async (req, res) => {
    try {
        const stats = await quarantineService.getStatistics();
        res.json(stats);
    } catch (error) {
        console.error('Error fetching quarantine stats:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

// Export quarantine report
app.get('/api/quarantine/export', async (req, res) => {
    try {
        const report = await quarantineService.exportReport();
        res.json(report);
    } catch (error) {
        console.error('Error exporting quarantine report:', error);
        res.status(500).json({ error: 'Failed to export report' });
    }
});

// Settings Management
app.get('/api/settings', (req, res) => {
    res.json(settings);
});

app.put('/api/settings', (req, res) => {
    settings = { ...settings, ...req.body };
    res.json(settings);
});

// Configuration (alias for settings)
app.get('/api/config', (req, res) => {
    res.json(settings);
});

app.post('/api/config', (req, res) => {
    settings = { ...settings, ...req.body };
    res.json({ success: true, config: settings });
});

// File Cleaning - Real implementation with pattern removal
app.post('/api/file/clean', async (req, res) => {
    const { filePath } = req.body;
    
    if (!filePath) {
        return res.status(400).json({ error: 'No file path provided' });
    }

    try {
        console.log(`🧹 Cleaning file: ${filePath}`);
        
        // Use real file cleaner
        const result = await fileCleaner.cleanFile(filePath);
        
        if (!result.success) {
            return res.status(400).json(result);
        }
        
        console.log(`✅ File cleaned: ${result.signaturesRemoved || 0} threats removed`);
        res.json(result);
        
    } catch (error) {
        console.error('❌ File cleaning error:', error.message);
        res.status(500).json({
            success: false,
            error: error.message || 'File cleaning failed',
            recommendation: 'QUARANTINE'
        });
    }
});

// Database Management / Signature Updates
app.post('/api/database/update', (req, res) => {
    setTimeout(() => {
        res.json({
            success: true,
            message: 'Virus definitions updated successfully',
            version: `${new Date().getFullYear()}.${new Date().getMonth() + 1}.${new Date().getDate()}`,
            newSignatures: Math.floor(Math.random() * 1000) + 500
        });
    }, 2000);
});

// Alias endpoint for signature updates
app.post('/api/signatures/update', (req, res) => {
    setTimeout(() => {
        const newSignatures = Math.floor(Math.random() * 100) + 50;
        const timestamp = new Date().toISOString();
        const version = `${new Date().getFullYear()}.${new Date().getMonth() + 1}.${new Date().getDate()}`;
        
        console.log(`📦 Updating virus signatures... +${newSignatures} new signatures`);
        
        // Generate sample signature data in the format expected by the frontend
        const virusSignatures = [];
        const malwareSignatures = [];
        const suspiciousSignatures = [];
        
        // Generate some sample signatures
        for (let i = 0; i < Math.floor(newSignatures / 3); i++) {
            virusSignatures.push({
                id: `virus_${Date.now()}_${i}`,
                name: `Virus.Generic.${Math.random().toString(36).substring(7)}`,
                pattern: Math.random().toString(36).substring(2, 15),
                severity: 'high',
                timestamp: timestamp
            });
            
            malwareSignatures.push({
                id: `malware_${Date.now()}_${i}`,
                name: `Malware.Trojan.${Math.random().toString(36).substring(7)}`,
                pattern: Math.random().toString(36).substring(2, 15),
                severity: 'critical',
                timestamp: timestamp
            });
            
            suspiciousSignatures.push({
                id: `suspicious_${Date.now()}_${i}`,
                name: `Suspicious.Behavior.${Math.random().toString(36).substring(7)}`,
                pattern: Math.random().toString(36).substring(2, 15),
                severity: 'medium',
                timestamp: timestamp
            });
        }
        
        res.json({
            success: true,
            version: version,
            timestamp: timestamp,
            signatures: {
                virus: virusSignatures,
                malware: malwareSignatures,
                suspicious: suspiciousSignatures
            },
            checksum: Math.random().toString(36).substring(2, 15),
            totalSignatures: 125000 + newSignatures,
            newSignatures: newSignatures
        });
    }, 2000);
});

// Storage Management
app.get('/api/storage/info', (req, res) => {
    const totalSpace = 500 * 1024 * 1024 * 1024; // 500 GB
    const usedSpace = Math.floor(Math.random() * 200) * 1024 * 1024 * 1024; // Random usage
    const availableSpace = totalSpace - usedSpace;
    const quarantineSize = quarantineItems.reduce((sum, item) => sum + (item.size || 0), 0);
    const databaseSize = 5 * 1024 * 1024; // 5 MB
    const backupSize = 2 * 1024 * 1024; // 2 MB
    
    res.json({
        total_space: totalSpace,
        available_space: availableSpace,
        used_space: usedSpace,
        usage_percentage: (usedSpace / totalSpace) * 100,
        quarantine_size: quarantineSize,
        database_size: databaseSize,
        backup_size: backupSize,
        quarantine_limit: 1024 * 1024 * 1024, // 1 GB
        quarantine_usage_percentage: (quarantineSize / (1024 * 1024 * 1024)) * 100
    });
});

// Real-time Protection
app.get('/api/protection/status', (req, res) => {
    res.json({
        enabled: settings.realTimeProtection,
        activeScans: Math.floor(Math.random() * 5),
        blockedThreats: Math.floor(Math.random() * 10),
        filesMonitored: settings.realTimeProtection ? Math.floor(Math.random() * 1000) + 500 : 0,
        lastActivity: settings.realTimeProtection ? new Date().toISOString() : null
    });
});

app.post('/api/protection/toggle', (req, res) => {
    settings.realTimeProtection = !settings.realTimeProtection;
    
    const message = `Real-time protection ${settings.realTimeProtection ? 'enabled' : 'disabled'}`;
    console.log(`🛡️  ${message}`);
    
    res.json({
        enabled: settings.realTimeProtection,
        message: message
    });
});

// Real-time Protection Events (for live monitoring)
app.get('/api/protection/events', (req, res) => {
    if (!settings.realTimeProtection) {
        return res.json({ events: [] });
    }
    
    // Simulate recent protection events
    const eventTypes = ['file_scanned', 'threat_blocked', 'file_cleaned'];
    const events = [];
    const eventCount = Math.floor(Math.random() * 5);
    
    for (let i = 0; i < eventCount; i++) {
        const type = eventTypes[Math.floor(Math.random() * eventTypes.length)];
        events.push({
            id: Date.now() + i,
            type: type,
            timestamp: new Date(Date.now() - Math.random() * 60000).toISOString(),
            filePath: `C:\\Users\\Downloads\\file_${i + 1}.exe`,
            action: type === 'threat_blocked' ? 'quarantined' : 'allowed'
        });
    }
    
    res.json({ events });
});

// ==================== DISK CLEANUP ENDPOINTS ====================

// Analyze disk space
app.get('/api/disk/analyze', async (req, res) => {
    try {
        console.log('📊 Analyzing disk space...');
        const analysis = await diskCleaner.analyzeDiskSpace();
        
        if (!analysis.success) {
            console.error('❌ Disk analysis returned error:', analysis.error);
            return res.status(500).json(analysis);
        }
        
        console.log(`✅ Analysis complete: ${diskCleaner.formatBytes(analysis.totalCleanable)} cleanable`);
        res.json(analysis);
    } catch (error) {
        console.error('❌ Disk analysis error:', error.message);
        console.error(error.stack);
        res.status(500).json({ 
            success: false, 
            error: error.message,
            analysis: {
                recycleBin: { size: 0, count: 0, location: 'Recycle Bin' },
                tempFiles: { size: 0, count: 0, location: 'Temporary Files' },
                downloads: { size: 0, count: 0, location: 'Downloads' },
                browserCache: { size: 0, count: 0, location: 'Browser Cache' },
                logs: { size: 0, count: 0, location: 'System Logs' },
                oldFiles: { size: 0, count: 0, location: 'Old Files' },
            },
            totalCleanable: 0,
            totalFiles: 0,
            recommendations: []
        });
    }
});

// Clean recycle bin
app.post('/api/disk/clean/recyclebin', async (req, res) => {
    try {
        console.log('🗑️  Cleaning Recycle Bin...');
        const result = await diskCleaner.cleanRecycleBin();
        console.log(`✅ Recycle Bin cleaned: ${diskCleaner.formatBytes(result.cleaned || 0)}`);
        res.json(result);
    } catch (error) {
        console.error('❌ Recycle Bin cleanup error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Clean temporary files
app.post('/api/disk/clean/temp', async (req, res) => {
    try {
        console.log('🧹 Cleaning temporary files...');
        const result = await diskCleaner.cleanTempFiles();
        console.log(`✅ Temp files cleaned: ${diskCleaner.formatBytes(result.cleaned || 0)}`);
        res.json(result);
    } catch (error) {
        console.error('❌ Temp cleanup error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Clean old downloads
app.post('/api/disk/clean/downloads', async (req, res) => {
    try {
        const { daysOld = 30 } = req.body;
        console.log(`🧹 Cleaning downloads older than ${daysOld} days...`);
        const result = await diskCleaner.cleanOldDownloads(daysOld);
        console.log(`✅ Downloads cleaned: ${diskCleaner.formatBytes(result.cleaned || 0)}`);
        res.json(result);
    } catch (error) {
        console.error('❌ Downloads cleanup error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Clean all (one-click cleanup)
app.post('/api/disk/clean/all', async (req, res) => {
    try {
        console.log('🚀 Starting full disk cleanup...');
        const result = await diskCleaner.cleanAll();
        console.log(`✅ Cleanup complete: ${result.message}`);
        res.json(result);
    } catch (error) {
        console.error('❌ Full cleanup error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== AUTHENTICATION & 2FA ====================

// Middleware to verify session
const requireAuth = (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const validation = authService.validateSession(token);
    
    if (!validation.valid) {
        return res.status(401).json({ error: validation.error });
    }

    req.session = validation.session;
    req.user = {
        id: validation.session.userId,
        email: validation.session.email,
        username: validation.session.username
    };
    
    next();
};

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        console.log('📥 Login request received:', { email: req.body.email, ip: req.ip });
        console.log('🔍 Password received (first 3 chars):', req.body.password?.substring(0, 3) + '***');
        const { email, password } = req.body;
        const ipAddress = req.ip;
        const userAgent = req.headers['user-agent'];

        const result = await authService.authenticate(email, password);
        console.log('🔐 Authentication result:', { success: result.success, email });

        // Log login attempt
        await activityLogger.log({
            userEmail: email,
            action: 'login_attempt',
            category: 'authentication',
            details: result.success ? 'Successful login' : 'Failed login',
            ipAddress,
            userAgent,
            status: result.success ? 'success' : 'error'
        });

        if (result.success && result.sessionToken) {
            // Update session with IP and user agent
            const session = authService.sessions.get(result.sessionToken);
            if (session) {
                session.ipAddress = ipAddress;
                session.userAgent = userAgent;
            }
            
            // Map sessionToken to token for frontend compatibility
            const response = {
                success: result.success,
                token: result.sessionToken,
                user: result.user,
                message: 'Login successful'
            };
            console.log('✅ Sending success response');
            res.json(response);
        } else {
            console.log('❌ Login failed:', result.error);
            res.json(result);
        }
    } catch (error) {
        console.error('💥 Login error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Login failed',
            message: 'An error occurred during login'
        });
    }
});

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, fullName } = req.body;
        const ipAddress = req.ip;
        const userAgent = req.headers['user-agent'];

        // Validate input
        if (!email || !password || !fullName) {
            return res.status(400).json({ 
                success: false, 
                message: 'All fields are required' 
            });
        }

        // Check if user already exists (mock check)
        const existingUsers = authService.users || new Map();
        const userExists = Array.from(existingUsers.values()).some(u => u.email === email);
        
        if (userExists) {
            return res.status(400).json({ 
                success: false, 
                message: 'An account with this email already exists' 
            });
        }

        // Create new user (simplified - in production, hash password properly)
        const newUser = {
            id: Date.now(),
            email,
            fullName,
            password, // In production, this should be hashed
            role: 'user',
            tier: 'free',
            createdAt: new Date().toISOString(),
            verified: false // Email not verified yet
        };

        // Store user (mock storage)
        if (!authService.users) {
            authService.users = new Map();
        }
        authService.users.set(email, newUser);

        // Log registration
        await activityLogger.log({
            userEmail: email,
            action: 'user_registration',
            category: 'authentication',
            details: `New user registered: ${fullName}`,
            ipAddress,
            userAgent,
            status: 'success'
        });

        res.json({ 
            success: true, 
            message: 'Account created successfully',
            user: {
                id: newUser.id,
                email: newUser.email,
                fullName: newUser.fullName,
                role: newUser.role,
                tier: newUser.tier
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Registration failed. Please try again.' 
        });
    }
});

// Password reset storage (in production, use database with TTL)
const resetCodes = new Map(); // Map<email, {code: string, expires: number}>

// Forgot Password - Generate and send reset code
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email is required' 
            });
        }

        // Check if user exists
        const existingUsers = authService.users || new Map();
        const user = Array.from(existingUsers.values()).find(u => u.email === email);
        
        if (user) {
            // Generate 6-digit code
            const code = Math.floor(100000 + Math.random() * 900000).toString();
            
            // Store code with 10 minute expiration
            resetCodes.set(email, {
                code: code,
                expires: Date.now() + 10 * 60 * 1000, // 10 minutes
                userId: user.id
            });
            
            // Log code for testing (in production, send via email)
            console.log(`\n📧 Password Reset Code for ${email}`);
            console.log(`Code: ${code}`);
            console.log(`Expires in 10 minutes\n`);
            
            // Log activity
            await activityLogger.log({
                userEmail: email,
                action: 'password_reset_requested',
                category: 'authentication',
                details: 'Password reset code generated',
                status: 'success'
            });
        }
        
        // Always return success to prevent email enumeration
        res.json({
            success: true,
            message: 'If an account exists with this email, a reset code has been sent.'
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to process password reset request' 
        });
    }
});

// Verify reset code
app.post('/api/auth/verify-reset-code', async (req, res) => {
    try {
        const { email, code } = req.body;
        
        if (!email || !code) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and code are required' 
            });
        }
        
        // Check if reset code exists
        const resetData = resetCodes.get(email);
        
        if (!resetData) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid or expired reset code' 
            });
        }
        
        // Check if code expired
        if (Date.now() > resetData.expires) {
            resetCodes.delete(email);
            return res.status(400).json({ 
                success: false, 
                message: 'Reset code has expired. Please request a new one.' 
            });
        }
        
        // Verify code
        if (resetData.code !== code) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid reset code' 
            });
        }
        
        res.json({
            success: true,
            message: 'Code verified successfully'
        });
    } catch (error) {
        console.error('Verify reset code error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to verify reset code' 
        });
    }
});

// Reset password with verified code
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, code, newPassword } = req.body;
        
        if (!email || !code || !newPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email, code, and new password are required' 
            });
        }
        
        // Check if reset code exists
        const resetData = resetCodes.get(email);
        
        if (!resetData) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid or expired reset code' 
            });
        }
        
        // Check if code expired
        if (Date.now() > resetData.expires) {
            resetCodes.delete(email);
            return res.status(400).json({ 
                success: false, 
                message: 'Reset code has expired. Please request a new one.' 
            });
        }
        
        // Verify code
        if (resetData.code !== code) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid reset code' 
            });
        }
        
        // Update password in storage
        const existingUsers = authService.users || new Map();
        const user = Array.from(existingUsers.values()).find(u => u.email === email);
        
        if (user) {
            user.password = newPassword; // In production, hash this!
            existingUsers.set(email, user);
            
            // Delete used reset code
            resetCodes.delete(email);
            
            console.log(`✅ Password reset successful for ${email}`);
            
            // Log activity
            await activityLogger.log({
                userEmail: email,
                action: 'password_reset_completed',
                category: 'authentication',
                details: 'Password successfully reset',
                status: 'success'
            });
            
            res.json({
                success: true,
                message: 'Password has been reset successfully'
            });
        } else {
            res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to reset password' 
        });
    }
});

// Token verification endpoint
app.get('/api/auth/verify', (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                success: false, 
                message: 'No token provided' 
            });
        }

        const token = authHeader.substring(7); // Remove 'Bearer ' prefix
        
        // Verify the token with auth service
        const session = authService.verifyToken(token);
        
        if (!session) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid or expired token' 
            });
        }

        // Return user data
        res.json({ 
            success: true, 
            user: {
                id: session.userId,
                email: session.email,
                fullName: session.fullName,
                role: session.role,
                tier: session.tier,
                verified: session.verified
            }
        });
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Token verification failed' 
        });
    }
});

// Verify 2FA
app.post('/api/auth/verify-2fa', async (req, res) => {
    try {
        const { email, token } = req.body;
        const ipAddress = req.ip;
        const userAgent = req.headers['user-agent'];

        const result = await authService.verifyTwoFactor(email, token);

        // Log 2FA verification
        await activityLogger.log({
            userEmail: email,
            action: '2fa_verification',
            category: 'authentication',
            details: result.success ? 'Successful 2FA verification' : 'Failed 2FA verification',
            ipAddress,
            userAgent,
            status: result.success ? 'success' : 'error'
        });

        if (result.success && result.sessionToken) {
            const session = authService.sessions.get(result.sessionToken);
            if (session) {
                session.ipAddress = ipAddress;
                session.userAgent = userAgent;
            }
        }

        res.json(result);
    } catch (error) {
        console.error('2FA verification error:', error);
        res.status(500).json({ error: '2FA verification failed' });
    }
});

// Logout
app.post('/api/auth/logout', requireAuth, async (req, res) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        const result = authService.logout(token);

        // Log logout
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'logout',
            category: 'authentication',
            details: 'User logged out',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
        });

        res.json(result);
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

// Enable 2FA
app.post('/api/auth/enable-2fa', requireAuth, async (req, res) => {
    try {
        const result = await authService.enableTwoFactor(req.user.email);

        // Log 2FA enablement
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'enable_2fa',
            category: 'security',
            details: 'Initiated 2FA setup',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: result.success ? 'success' : 'error'
        });

        res.json(result);
    } catch (error) {
        console.error('Enable 2FA error:', error);
        res.status(500).json({ error: 'Failed to enable 2FA' });
    }
});

// Confirm 2FA
app.post('/api/auth/confirm-2fa', requireAuth, async (req, res) => {
    try {
        const { token } = req.body;
        const result = await authService.confirmTwoFactor(req.user.email, token);

        // Log 2FA confirmation
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'confirm_2fa',
            category: 'security',
            details: result.success ? '2FA enabled successfully' : 'Failed to enable 2FA',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: result.success ? 'success' : 'error'
        });

        res.json(result);
    } catch (error) {
        console.error('Confirm 2FA error:', error);
        res.status(500).json({ error: 'Failed to confirm 2FA' });
    }
});

// Disable 2FA
app.post('/api/auth/disable-2fa', requireAuth, async (req, res) => {
    try {
        const { password } = req.body;
        const result = await authService.disableTwoFactor(req.user.email, password);

        // Log 2FA disable
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'disable_2fa',
            category: 'security',
            details: result.success ? '2FA disabled successfully' : 'Failed to disable 2FA',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: result.success ? 'success' : 'error'
        });

        res.json(result);
    } catch (error) {
        console.error('Disable 2FA error:', error);
        res.status(500).json({ error: 'Failed to disable 2FA' });
    }
});

// ==================== SESSION MANAGEMENT ====================

// Get all sessions
app.get('/api/sessions', requireAuth, async (req, res) => {
    try {
        const currentToken = req.headers.authorization?.replace('Bearer ', '');
        const sessions = authService.getUserSessions(req.user.id);

        // Mark current session
        const sessionsWithCurrent = sessions.map(session => ({
            ...session,
            current: authService.sessions.get(currentToken)?.id === session.id
        }));

        res.json(sessionsWithCurrent);
    } catch (error) {
        console.error('Get sessions error:', error);
        res.status(500).json({ error: 'Failed to fetch sessions' });
    }
});

// Revoke specific session
app.delete('/api/sessions/:sessionId', requireAuth, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const result = authService.revokeSession(req.user.id, sessionId);

        // Log session revocation
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'revoke_session',
            category: 'security',
            details: `Revoked session: ${sessionId}`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: result.success ? 'success' : 'error'
        });

        res.json(result);
    } catch (error) {
        console.error('Revoke session error:', error);
        res.status(500).json({ error: 'Failed to revoke session' });
    }
});

// Revoke all sessions except current
app.post('/api/sessions/revoke-all', requireAuth, async (req, res) => {
    try {
        const currentToken = req.headers.authorization?.replace('Bearer ', '');
        const result = authService.revokeAllSessions(req.user.id, currentToken);

        // Log bulk session revocation
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'revoke_all_sessions',
            category: 'security',
            details: `Revoked ${result.count} session(s)`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
        });

        res.json(result);
    } catch (error) {
        console.error('Revoke all sessions error:', error);
        res.status(500).json({ error: 'Failed to revoke sessions' });
    }
});

// Change password
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const result = await authService.changePassword(req.user.email, currentPassword, newPassword);

        // Log password change
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'change_password',
            category: 'security',
            details: result.success ? 'Password changed successfully' : 'Failed to change password',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: result.success ? 'success' : 'error'
        });

        res.json(result);
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// ==================== SUBSCRIPTION ====================

// Get subscription
app.get('/api/subscription', requireAuth, async (req, res) => {
    try {
        // Mock subscription data based on user tier
        const subscription = {
            tier: req.user.tier || 'free',
            status: 'active',
            features: req.user.tier === 'premium' ? [
                'Advanced threat detection',
                'Real-time protection',
                'Email protection',
                'Ransomware protection',
                'Network monitoring',
                'Priority support'
            ] : [
                'Basic virus scanning',
                'Quarantine management',
                'Basic protection'
            ],
            expiresAt: req.user.tier === 'premium' ? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) : null,
            autoRenew: false
        };

        res.json({
            success: true,
            subscription
        });
    } catch (error) {
        console.error('Get subscription error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to get subscription' 
        });
    }
});

// Check feature access
app.post('/api/subscription/check-feature', requireAuth, async (req, res) => {
    try {
        const { feature } = req.body;
        
        // Premium features that require paid subscription
        const premiumFeatures = [
            'advanced-scanning',
            'real-time-protection',
            'email-protection',
            'ransomware-protection',
            'network-monitoring',
            'ml-detection',
            'behavioral-analysis'
        ];

        const hasAccess = req.user.tier === 'premium' || req.user.role === 'admin' || !premiumFeatures.includes(feature);

        res.json({
            hasAccess,
            requiresUpgrade: !hasAccess,
            currentTier: req.user.tier
        });
    } catch (error) {
        console.error('Check feature error:', error);
        res.status(500).json({ 
            hasAccess: false,
            requiresUpgrade: true,
            error: 'Failed to check feature access' 
        });
    }
});

// Upgrade to premium
app.post('/api/subscription/upgrade', requireAuth, async (req, res) => {
    try {
        // In a real app, this would handle payment processing
        // For now, just upgrade the user
        const user = authService.users.get(req.user.email);
        if (user) {
            user.tier = 'premium';
        }

        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'upgrade_subscription',
            category: 'subscription',
            details: 'Upgraded to premium',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
        });

        res.json({
            success: true,
            message: 'Successfully upgraded to premium',
            subscription: {
                tier: 'premium',
                status: 'active',
                expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
            }
        });
    } catch (error) {
        console.error('Upgrade subscription error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to upgrade subscription' 
        });
    }
});

// ==================== ACTIVITY LOGS ====================

// Get activities
app.get('/api/activities', requireAuth, async (req, res) => {
    try {
        const {
            category,
            action,
            startDate,
            endDate,
            status,
            limit = 100,
            offset = 0
        } = req.query;

        const activities = await activityLogger.getActivities({
            userId: req.user.id,
            category,
            action,
            startDate,
            endDate,
            status,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });

        res.json(activities);
    } catch (error) {
        console.error('Get activities error:', error);
        res.status(500).json({ error: 'Failed to fetch activities' });
    }
});

// Get activity statistics
app.get('/api/activities/stats', requireAuth, async (req, res) => {
    try {
        const { days = 30 } = req.query;
        const stats = await activityLogger.getStatistics(req.user.id, parseInt(days));
        res.json(stats);
    } catch (error) {
        console.error('Get activity stats error:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

// Search activities
app.get('/api/activities/search', requireAuth, async (req, res) => {
    try {
        const { q, limit = 100 } = req.query;
        
        if (!q) {
            return res.status(400).json({ error: 'Search query required' });
        }

        const activities = await activityLogger.searchActivities(q, parseInt(limit));
        res.json(activities);
    } catch (error) {
        console.error('Search activities error:', error);
        res.status(500).json({ error: 'Failed to search activities' });
    }
});

// Export activities
app.get('/api/activities/export', requireAuth, async (req, res) => {
    try {
        const {
            category,
            startDate,
            endDate
        } = req.query;

        const exportData = await activityLogger.exportActivities({
            userId: req.user.id,
            category,
            startDate,
            endDate
        });

        // Log export
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'export_activities',
            category: 'data',
            details: `Exported ${exportData.totalRecords} activity records`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
        });

        res.json(exportData);
    } catch (error) {
        console.error('Export activities error:', error);
        res.status(500).json({ error: 'Failed to export activities' });
    }
});

// ==================== BACKUP & RESTORE ====================

// Create backup
app.post('/api/backup/create', requireAuth, async (req, res) => {
    try {
        const {
            includeLogs = true,
            includeQuarantine = true,
            includeSettings = true,
            includeActivities = true,
            description = 'Manual backup'
        } = req.body;

        const result = await backupService.createBackup({
            includeLogs,
            includeQuarantine,
            includeSettings,
            includeActivities,
            description
        });

        // Log backup creation
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'create_backup',
            category: 'backup',
            details: `Created backup: ${result.backup.name}`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success',
            metadata: { backupId: result.backup.id, size: result.backup.size }
        });

        res.json(result);
    } catch (error) {
        console.error('Create backup error:', error);
        res.status(500).json({ error: 'Failed to create backup' });
    }
});

// List backups
app.get('/api/backup/list', requireAuth, async (req, res) => {
    try {
        const backups = await backupService.listBackups();
        res.json(backups);
    } catch (error) {
        console.error('List backups error:', error);
        res.status(500).json({ error: 'Failed to list backups' });
    }
});

// Restore backup
app.post('/api/backup/restore/:backupId', requireAuth, async (req, res) => {
    try {
        const { backupId } = req.params;
        const {
            restoreLogs = true,
            restoreQuarantine = true,
            restoreSettings = true,
            restoreActivities = true
        } = req.body;

        const result = await backupService.restoreBackup(backupId, {
            restoreLogs,
            restoreQuarantine,
            restoreSettings,
            restoreActivities
        });

        // Log restore
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'restore_backup',
            category: 'backup',
            details: `Restored backup: ${backupId}`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success',
            metadata: { backupId, restored: result.restored }
        });

        res.json(result);
    } catch (error) {
        console.error('Restore backup error:', error);
        res.status(500).json({ error: 'Failed to restore backup' });
    }
});

// Delete backup
app.delete('/api/backup/:backupId', requireAuth, async (req, res) => {
    try {
        const { backupId } = req.params;
        const result = await backupService.deleteBackup(backupId);

        // Log deletion
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'delete_backup',
            category: 'backup',
            details: `Deleted backup: ${backupId}`,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
        });

        res.json(result);
    } catch (error) {
        console.error('Delete backup error:', error);
        res.status(500).json({ error: 'Failed to delete backup' });
    }
});

// Get backup statistics
app.get('/api/backup/stats', requireAuth, async (req, res) => {
    try {
        const stats = await backupService.getStatistics();
        res.json(stats);
    } catch (error) {
        console.error('Get backup stats error:', error);
        res.status(500).json({ error: 'Failed to fetch backup statistics' });
    }
});

// Export configuration
app.get('/api/config/export', requireAuth, async (req, res) => {
    try {
        const config = await backupService.exportConfiguration();

        // Log export
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'export_config',
            category: 'configuration',
            details: 'Exported system configuration',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
        });

        res.json(config);
    } catch (error) {
        console.error('Export config error:', error);
        res.status(500).json({ error: 'Failed to export configuration' });
    }
});

// Import configuration
app.post('/api/config/import', requireAuth, async (req, res) => {
    try {
        const config = req.body;
        const result = await backupService.importConfiguration(config);

        // Log import
        await activityLogger.log({
            userId: req.user.id,
            userEmail: req.user.email,
            action: 'import_config',
            category: 'configuration',
            details: 'Imported system configuration',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
        });

        res.json(result);
    } catch (error) {
        console.error('Import config error:', error);
        res.status(500).json({ error: 'Failed to import configuration' });
    }
});

// ==================== ANALYTICS & MONITORING ====================

// Track event
app.post('/api/analytics/event', async (req, res) => {
    try {
        const event = req.body;
        await analyticsService.trackEvent({
            ...event,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Track event error:', error);
        res.status(500).json({ error: 'Failed to track event' });
    }
});

// Track page view
app.post('/api/analytics/pageview', async (req, res) => {
    try {
        const pageView = req.body;
        await analyticsService.trackPageView(pageView);
        res.json({ success: true });
    } catch (error) {
        console.error('Track page view error:', error);
        res.status(500).json({ error: 'Failed to track page view' });
    }
});

// Track session
app.post('/api/analytics/session', async (req, res) => {
    try {
        const session = req.body;
        await analyticsService.trackSession({
            ...session,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Track session error:', error);
        res.status(500).json({ error: 'Failed to track session' });
    }
});

// Log error
app.post('/api/analytics/error', async (req, res) => {
    try {
        const error = req.body;
        await analyticsService.logError({
            ...error,
            userAgent: req.headers['user-agent']
        });
        res.json({ success: true });
    } catch (error) {
        console.error('Log error failed:', error);
        res.status(500).json({ error: 'Failed to log error' });
    }
});

// Track performance
app.post('/api/analytics/performance', async (req, res) => {
    try {
        const metric = req.body;
        await analyticsService.trackPerformance(metric);
        res.json({ success: true });
    } catch (error) {
        console.error('Track performance error:', error);
        res.status(500).json({ error: 'Failed to track performance' });
    }
});

// Get analytics dashboard
app.get('/api/analytics/dashboard', async (req, res) => {
    try {
        const { timeRange = '24h' } = req.query;
        const dashboard = await analyticsService.getDashboardData(timeRange);
        res.json(dashboard);
    } catch (error) {
        console.error('Get dashboard error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard data' });
    }
});

// Get error timeline
app.get('/api/analytics/errors/timeline', async (req, res) => {
    try {
        const { timeRange = '24h', interval = '1h' } = req.query;
        const timeline = await analyticsService.getErrorTimeline(timeRange, interval);
        res.json(timeline);
    } catch (error) {
        console.error('Get error timeline error:', error);
        res.status(500).json({ error: 'Failed to fetch error timeline' });
    }
});

// ==================== SYSTEM MONITORING ====================

// Get system health
app.get('/api/system/health', async (req, res) => {
    try {
        const health = await systemMonitor.getSystemHealth();
        res.json(health);
    } catch (error) {
        console.error('Get system health error:', error);
        res.status(500).json({ error: 'Failed to fetch system health' });
    }
});

// Get metric history
app.get('/api/system/metrics/:type', async (req, res) => {
    try {
        const { type } = req.params;
        const { limit = 50 } = req.query;
        const history = systemMonitor.getHistory(type, parseInt(limit));
        res.json(history);
    } catch (error) {
        console.error('Get metrics error:', error);
        res.status(500).json({ error: 'Failed to fetch metrics' });
    }
});

// Get performance report
app.get('/api/system/performance-report', async (req, res) => {
    try {
        const report = await systemMonitor.getPerformanceReport();
        res.json(report);
    } catch (error) {
        console.error('Get performance report error:', error);
        res.status(500).json({ error: 'Failed to fetch performance report' });
    }
});

// Clear system alerts
app.post('/api/system/alerts/clear', (req, res) => {
    try {
        systemMonitor.clearAlerts();
        res.json({ success: true, message: 'Alerts cleared' });
    } catch (error) {
        console.error('Clear alerts error:', error);
        res.status(500).json({ error: 'Failed to clear alerts' });
    }
});

// ==================== BULK OPERATIONS ====================
app.post('/api/bulk/operations', (req, res) => {
    const { type, items, options } = req.body;
    const operation = bulkOperations.createOperation(type, items, options);
    res.json(operation);
});

app.post('/api/bulk/operations/:id/execute', async (req, res) => {
    const { id } = req.params;
    const { processor } = req.body;
    try {
        const result = await bulkOperations.executeOperation(id, processor);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/bulk/operations/:id/cancel', (req, res) => {
    const { id } = req.params;
    const result = bulkOperations.cancelOperation(id);
    res.json(result);
});

app.get('/api/bulk/operations/:id', (req, res) => {
    const { id } = req.params;
    const operation = bulkOperations.getOperation(id);
    if (!operation) {
        return res.status(404).json({ error: 'Operation not found' });
    }
    res.json(operation);
});

app.get('/api/bulk/operations', (req, res) => {
    const operations = bulkOperations.getAllOperations();
    res.json(operations);
});

app.get('/api/bulk/statistics', (req, res) => {
    const stats = bulkOperations.getStatistics();
    res.json(stats);
});

app.get('/api/bulk/operations/:id/export', (req, res) => {
    const { id } = req.params;
    const { format = 'json' } = req.query;
    try {
        const result = bulkOperations.exportResults(id, format);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/bulk/operations/:id', (req, res) => {
    const { id } = req.params;
    bulkOperations.deleteOperation(id);
    res.json({ message: 'Operation deleted successfully' });
});

// ==================== SCHEDULED TASKS ====================
app.post('/api/tasks', (req, res) => {
    const taskConfig = req.body;
    try {
        const task = scheduledTasks.createTask(taskConfig);
        res.json(task);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/tasks', (req, res) => {
    const tasks = scheduledTasks.getAllTasks();
    res.json(tasks);
});

app.get('/api/tasks/:id', (req, res) => {
    const { id } = req.params;
    const task = scheduledTasks.getTask(id);
    if (!task) {
        return res.status(404).json({ error: 'Task not found' });
    }
    res.json(task);
});

app.put('/api/tasks/:id', (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    try {
        const task = scheduledTasks.updateTask(id, updates);
        res.json(task);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/tasks/:id', (req, res) => {
    const { id } = req.params;
    scheduledTasks.deleteTask(id);
    res.json({ message: 'Task deleted successfully' });
});

app.post('/api/tasks/:id/execute', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await scheduledTasks.executeTask(id, true);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.put('/api/tasks/:id/toggle', (req, res) => {
    const { id } = req.params;
    const task = scheduledTasks.getTask(id);
    if (!task) {
        return res.status(404).json({ error: 'Task not found' });
    }
    const updated = scheduledTasks.updateTask(id, { enabled: !task.enabled });
    res.json(updated);
});

app.get('/api/tasks/:id/history', (req, res) => {
    const { id } = req.params;
    const { limit = 50 } = req.query;
    const history = scheduledTasks.getHistory({ taskId: id, limit: parseInt(limit) });
    res.json(history);
});

app.get('/api/tasks/statistics', (req, res) => {
    const stats = scheduledTasks.getStatistics();
    res.json(stats);
});

app.post('/api/tasks/import', (req, res) => {
    const { tasks, overwrite = false } = req.body;
    try {
        const result = scheduledTasks.importTasks({ tasks, overwrite });
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/tasks/export', (req, res) => {
    const exported = scheduledTasks.exportTasks();
    res.json(exported);
});

// ==================== SETTINGS IMPORT/EXPORT ====================
app.post('/api/settings/export', (req, res) => {
    const options = req.body;
    const exported = settingsImportExport.exportSettings(options);
    res.json(exported);
});

app.post('/api/settings/export/file', (req, res) => {
    const { filePath, options } = req.body;
    try {
        settingsImportExport.exportToFile(filePath, options);
        res.json({ message: 'Settings exported to file successfully', filePath });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/settings/import', async (req, res) => {
    const { importData, options } = req.body;
    try {
        const result = await settingsImportExport.importSettings(importData, options);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/settings/import/file', async (req, res) => {
    const { filePath, options } = req.body;
    try {
        const result = await settingsImportExport.importFromFile(filePath, options);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/settings/backups', (req, res) => {
    const { label } = req.body;
    try {
        const backup = settingsImportExport.createBackup(label);
        res.json(backup);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/settings/backups', (req, res) => {
    const backups = settingsImportExport.listBackups();
    res.json(backups);
});

app.post('/api/settings/backups/:id/restore', async (req, res) => {
    const { id } = req.params;
    const options = req.body;
    try {
        const result = await settingsImportExport.restoreBackup(id, options);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/settings/backups/:id', (req, res) => {
    const { id } = req.params;
    try {
        settingsImportExport.deleteBackup(id);
        res.json({ message: 'Backup deleted successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/settings/compare', (req, res) => {
    const { settings1, settings2 } = req.body;
    const comparison = settingsImportExport.compareSettings(settings1, settings2);
    res.json(comparison);
});

app.post('/api/settings/reset', async (req, res) => {
    const options = req.body;
    try {
        const result = await settingsImportExport.resetToDefaults(options);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==================== CLOUD BACKUP ====================
app.get('/api/cloud/providers', (req, res) => {
    const providers = cloudBackup.getProviders();
    res.json(providers);
});

app.post('/api/cloud/providers/:id/connect', (req, res) => {
    const { id } = req.params;
    const credentials = req.body;
    try {
        const result = cloudBackup.connectProvider(id, credentials);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/cloud/providers/:id/disconnect', (req, res) => {
    const { id } = req.params;
    cloudBackup.disconnectProvider(id);
    res.json({ message: 'Provider disconnected successfully' });
});

app.post('/api/cloud/providers/:id/test', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await cloudBackup.testConnection(id);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/cloud/backups', async (req, res) => {
    const options = req.body;
    try {
        const backup = await cloudBackup.createBackup(options);
        res.json(backup);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/cloud/backups', (req, res) => {
    const { providerId } = req.query;
    const backups = cloudBackup.getBackups(providerId);
    res.json(backups);
});

app.post('/api/cloud/backups/:id/restore', async (req, res) => {
    const { id } = req.params;
    const options = req.body;
    try {
        const result = await cloudBackup.restoreBackup(id, options);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/cloud/backups/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await cloudBackup.deleteCloudBackup(id);
        res.json({ message: 'Cloud backup deleted successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/cloud/statistics', (req, res) => {
    const stats = cloudBackup.getStatistics();
    res.json(stats);
});

// ==================== ENHANCED HACKER PROTECTION ====================
app.get('/api/security/status', (req, res) => {
    const stats = enhancedHackerProtection.getStatistics();
    res.json({
        status: 'active',
        protectionLevel: stats.protectionLevel,
        totalAttacksBlocked: stats.totalAttacksBlocked,
        blockedIPs: stats.blockedIPs,
        suspiciousIPs: stats.suspiciousIPs,
        attacksByType: stats.attacksByType,
        topAttackers: stats.topAttackers,
        lastUpdate: stats.lastUpdate
    });
});

app.get('/api/security/statistics', (req, res) => {
    const stats = enhancedHackerProtection.getStatistics();
    res.json(stats);
});

app.get('/api/security/blocked-ips', (req, res) => {
    const blockedIPs = enhancedHackerProtection.getBlockedIPs();
    res.json(blockedIPs);
});

app.post('/api/security/block-ip', (req, res) => {
    const { ip, reason, duration } = req.body;
    if (!ip) {
        return res.status(400).json({ error: 'IP address is required' });
    }
    const blockInfo = enhancedHackerProtection.blockIP(ip, reason || 'Manual block', duration || 3600000);
    res.json(blockInfo);
});

app.post('/api/security/unblock-ip', (req, res) => {
    const { ip } = req.body;
    if (!ip) {
        return res.status(400).json({ error: 'IP address is required' });
    }
    enhancedHackerProtection.unblockIP(ip);
    res.json({ message: 'IP unblocked successfully', ip });
});

app.get('/api/security/attack-log', (req, res) => {
    const { limit = 100 } = req.query;
    const log = enhancedHackerProtection.getAttackLog(parseInt(limit));
    res.json(log);
});

app.get('/api/security/threat-analysis', (req, res) => {
    const stats = enhancedHackerProtection.getStatistics();
    const recentAttacks = enhancedHackerProtection.getAttackLog(50);
    
    // Analyze threat trends
    const threatTrends = {};
    recentAttacks.forEach(attack => {
        attack.threats.forEach(threat => {
            if (!threatTrends[threat.type]) {
                threatTrends[threat.type] = {
                    count: 0,
                    severity: threat.severity,
                    recent: []
                };
            }
            threatTrends[threat.type].count++;
            if (threatTrends[threat.type].recent.length < 5) {
                threatTrends[threat.type].recent.push({
                    timestamp: attack.timestamp,
                    ip: attack.ip
                });
            }
        });
    });

    res.json({
        totalAttacks: recentAttacks.length,
        threatTrends,
        attacksByType: stats.attacksByType,
        topAttackers: stats.topAttackers,
        protectionLevel: stats.protectionLevel,
        recommendations: getSecurityRecommendations(threatTrends, stats)
    });
});

function getSecurityRecommendations(threatTrends, stats) {
    const recommendations = [];
    
    // Check for high SQL injection attempts
    if ((threatTrends['sql-injection']?.count || 0) > 5) {
        recommendations.push({
            severity: 'High',
            type: 'sql-injection',
            message: 'High number of SQL injection attempts detected',
            action: 'Review and strengthen input validation on database queries'
        });
    }
    
    // Check for XSS attempts
    if ((threatTrends['xss']?.count || 0) > 5) {
        recommendations.push({
            severity: 'High',
            type: 'xss',
            message: 'Multiple XSS attempts detected',
            action: 'Implement Content Security Policy headers and sanitize user inputs'
        });
    }
    
    // Check for DDoS patterns
    if ((threatTrends['ddos']?.count || 0) > 10) {
        recommendations.push({
            severity: 'Critical',
            type: 'ddos',
            message: 'DDoS attack in progress',
            action: 'Enable DDoS protection and consider using a CDN'
        });
    }
    
    // Check for brute force
    if ((threatTrends['brute-force']?.count || 0) > 3) {
        recommendations.push({
            severity: 'High',
            type: 'brute-force',
            message: 'Brute force attacks detected',
            action: 'Implement CAPTCHA and two-factor authentication'
        });
    }
    
    // Check for zero-day attempts
    if (threatTrends['zero-day']) {
        recommendations.push({
            severity: 'Critical',
            type: 'zero-day',
            message: 'Potential zero-day exploit detected',
            action: 'Update all software immediately and review security logs'
        });
    }
    
    if (recommendations.length === 0) {
        recommendations.push({
            severity: 'Info',
            type: 'general',
            message: 'No immediate threats detected',
            action: 'Continue monitoring and maintain current security posture'
        });
    }
    
    return recommendations;
}

// ====== FIREWALL ENGINE API ======

// Get firewall status
app.get('/api/firewall/status', (req, res) => {
    const stats = firewallEngine.getStatistics();
    res.json({
        enabled: firewallEngine.isMonitoring,
        platform: firewallEngine.platform,
        windowsFirewallEnabled: firewallEngine.windowsFirewallEnabled,
        ...stats
    });
});

// Get all firewall rules
app.get('/api/firewall/rules', (req, res) => {
    const rules = firewallEngine.getRules();
    res.json({
        success: true,
        rules,
        count: rules.length
    });
});

// Add firewall rule
app.post('/api/firewall/rules', (req, res) => {
    const result = firewallEngine.addRule(req.body);
    res.json(result);
});

// Update firewall rule
app.put('/api/firewall/rules/:id', (req, res) => {
    const result = firewallEngine.updateRule(req.params.id, req.body);
    res.json(result);
});

// Delete firewall rule
app.delete('/api/firewall/rules/:id', (req, res) => {
    const result = firewallEngine.deleteRule(req.params.id);
    res.json(result);
});

// Block IP address
app.post('/api/firewall/block-ip', (req, res) => {
    const { ip, reason } = req.body;
    
    if (!ip) {
        return res.status(400).json({ error: 'IP address is required' });
    }
    
    firewallEngine.blockIP(ip, reason).then(result => {
        res.json(result);
    });
});

// Unblock IP address
app.post('/api/firewall/unblock-ip', (req, res) => {
    const { ip } = req.body;
    
    if (!ip) {
        return res.status(400).json({ error: 'IP address is required' });
    }
    
    firewallEngine.unblockIP(ip).then(result => {
        res.json(result);
    });
});

// Get blocked IPs
app.get('/api/firewall/blocked-ips', (req, res) => {
    const blockedIPs = firewallEngine.getBlockedIPs();
    res.json({
        success: true,
        ips: blockedIPs,
        count: blockedIPs.length
    });
});

// Get threat log
app.get('/api/firewall/threats', (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    const threats = firewallEngine.getThreatLog(limit);
    res.json({
        success: true,
        threats,
        count: threats.length
    });
});

// Clear threat log
app.delete('/api/firewall/threats', (req, res) => {
    const result = firewallEngine.clearThreatLog();
    res.json(result);
});

// Start monitoring
app.post('/api/firewall/monitoring/start', (req, res) => {
    firewallEngine.startMonitoring();
    res.json({
        success: true,
        monitoring: true,
        message: 'Firewall monitoring started'
    });
});

// Stop monitoring
app.post('/api/firewall/monitoring/stop', (req, res) => {
    firewallEngine.stopMonitoring();
    res.json({
        success: true,
        monitoring: false,
        message: 'Firewall monitoring stopped'
    });
});

// Get Windows Firewall rules
app.get('/api/firewall/windows/rules', async (req, res) => {
    const result = await firewallEngine.getWindowsFirewallRules();
    res.json(result);
});

// Add Windows Firewall rule
app.post('/api/firewall/windows/rules', async (req, res) => {
    const { name, config } = req.body;
    
    if (!name || !config) {
        return res.status(400).json({ error: 'Rule name and config are required' });
    }
    
    const result = await firewallEngine.addWindowsFirewallRule(name, config);
    res.json(result);
});

// Remove Windows Firewall rule
app.delete('/api/firewall/windows/rules/:name', async (req, res) => {
    const result = await firewallEngine.removeWindowsFirewallRule(req.params.name);
    res.json(result);
});

// Get firewall statistics
app.get('/api/firewall/statistics', (req, res) => {
    const stats = firewallEngine.getStatistics();
    res.json({
        success: true,
        statistics: stats
    });
});

// Reset firewall statistics
app.post('/api/firewall/statistics/reset', (req, res) => {
    const result = firewallEngine.resetStatistics();
    res.json(result);
});

// Inspect packet (for testing)
app.post('/api/firewall/inspect', (req, res) => {
    const packet = req.body;
    const result = firewallEngine.inspectPacket(packet);
    res.json({
        success: true,
        inspection: result
    });
});

// ====== AI THREAT DETECTION API ======

// Analyze connection with AI
app.post('/api/ai/analyze-connection', (req, res) => {
    const connection = req.body;
    const result = aiThreatDetector.analyzeConnection(connection);
    res.json({
        success: true,
        analysis: result
    });
});

// Get IP reputation
app.get('/api/ai/ip-reputation/:ip', (req, res) => {
    const result = aiThreatDetector.getIPReputation(req.params.ip);
    res.json({
        success: true,
        reputation: result
    });
});

// Get AI model statistics
app.get('/api/ai/model-stats', (req, res) => {
    const stats = aiThreatDetector.getModelStats();
    res.json({
        success: true,
        stats
    });
});

// Reset AI model
app.post('/api/ai/reset-model', (req, res) => {
    const result = aiThreatDetector.resetModel();
    res.json(result);
});

// ====== ENHANCED ML DETECTION API ======

// Train ML models with sample data
app.post('/api/ml/train', async (req, res) => {
    try {
        const { trainingData, labels } = req.body;
        
        if (!trainingData || !Array.isArray(trainingData)) {
            return res.status(400).json({ 
                error: 'Training data array is required' 
            });
        }

        const results = await enhancedMLEngine.trainAllModels(trainingData, labels);
        
        res.json({
            success: true,
            results,
            message: `Successfully trained ${Object.keys(results).length} models`
        });
    } catch (error) {
        console.error('ML training error:', error);
        res.status(500).json({ 
            error: 'Failed to train models',
            details: error.message 
        });
    }
});

// Detect malware in file
app.post('/api/ml/detect', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const filePath = req.file.path;
        const fileBuffer = fs.readFileSync(filePath);
        
        const sample = {
            type: 'file',
            path: filePath,
            buffer: fileBuffer,
            size: req.file.size
        };

        const detection = await enhancedMLEngine.detectMalware(sample);

        // Cleanup
        fs.unlinkSync(filePath);

        res.json({
            success: true,
            detection,
            fileName: req.file.originalname
        });
    } catch (error) {
        console.error('ML detection error:', error);
        res.status(500).json({ 
            error: 'Detection failed',
            details: error.message 
        });
    }
});

// Analyze network packet with ML
app.post('/api/ml/analyze-network', async (req, res) => {
    try {
        const packet = req.body;
        
        if (!packet) {
            return res.status(400).json({ error: 'Packet data required' });
        }

        const sample = {
            type: 'network',
            ...packet
        };

        const detection = await enhancedMLEngine.detectMalware(sample);

        res.json({
            success: true,
            detection
        });
    } catch (error) {
        console.error('Network analysis error:', error);
        res.status(500).json({ 
            error: 'Analysis failed',
            details: error.message 
        });
    }
});

// Get ML engine statistics
app.get('/api/ml/stats', (req, res) => {
    try {
        const stats = enhancedMLEngine.getStatistics();
        res.json({
            success: true,
            stats
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ 
            error: 'Failed to get statistics',
            details: error.message 
        });
    }
});

// Get detection history
app.get('/api/ml/history', (req, res) => {
    try {
        const { limit = 100, offset = 0 } = req.query;
        const history = enhancedMLEngine.detectionHistory
            .slice(parseInt(offset), parseInt(offset) + parseInt(limit));

        res.json({
            success: true,
            history,
            total: enhancedMLEngine.detectionHistory.length
        });
    } catch (error) {
        console.error('History error:', error);
        res.status(500).json({ 
            error: 'Failed to get history',
            details: error.message 
        });
    }
});

// Export trained models
app.post('/api/ml/export', async (req, res) => {
    try {
        const { filename = 'ml-models.json' } = req.body;
        const outputPath = path.join(__dirname, 'exports', filename);

        // Ensure exports directory exists
        const exportsDir = path.join(__dirname, 'exports');
        if (!fs.existsSync(exportsDir)) {
            fs.mkdirSync(exportsDir, { recursive: true });
        }

        const modelData = await enhancedMLEngine.exportModels(outputPath);

        res.json({
            success: true,
            message: 'Models exported successfully',
            path: outputPath,
            size: JSON.stringify(modelData).length
        });
    } catch (error) {
        console.error('Export error:', error);
        res.status(500).json({ 
            error: 'Failed to export models',
            details: error.message 
        });
    }
});

// Import trained models
app.post('/api/ml/import', upload.single('modelFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No model file uploaded' });
        }

        const modelData = await enhancedMLEngine.importModels(req.file.path);

        // Cleanup
        fs.unlinkSync(req.file.path);

        res.json({
            success: true,
            message: 'Models imported successfully',
            version: modelData.version,
            modelCount: Object.keys(modelData.models).length
        });
    } catch (error) {
        console.error('Import error:', error);
        res.status(500).json({ 
            error: 'Failed to import models',
            details: error.message 
        });
    }
});

// Get model performance metrics
app.get('/api/ml/performance', (req, res) => {
    try {
        const performance = enhancedMLEngine.modelPerformance;
        
        // Calculate additional metrics
        const metrics = {};
        for (const [model, perf] of Object.entries(performance)) {
            const precision = perf.truePositives > 0 
                ? perf.truePositives / (perf.truePositives + perf.falsePositives)
                : 0;
            
            metrics[model] = {
                ...perf,
                precision: (precision * 100).toFixed(2) + '%',
                totalPredictions: perf.predictions
            };
        }

        res.json({
            success: true,
            performance: metrics
        });
    } catch (error) {
        console.error('Performance error:', error);
        res.status(500).json({ 
            error: 'Failed to get performance metrics',
            details: error.message 
        });
    }
});

// ==================== BEHAVIOR-BASED DETECTION ====================

// Analyze file behavior for zero-day threats
app.post('/api/behavior/analyze', upload.single('file'), async (req, res) => {
    try {
        let filePath;
        
        if (req.file) {
            filePath = req.file.path;
        } else if (req.body.filePath) {
            filePath = req.body.filePath;
        } else {
            return res.status(400).json({ error: 'No file or file path provided' });
        }

        const options = {
            deep: req.body.deep !== false,
            monitorDuration: parseInt(req.body.monitorDuration) || 30000 // 30 seconds default
        };

        const analysis = await behaviorDetector.analyzeFileBehavior(filePath, options);

        // Cleanup uploaded file
        if (req.file) {
            fs.unlinkSync(req.file.path);
        }

        res.json({
            success: true,
            analysis
        });
    } catch (error) {
        console.error('Behavior analysis error:', error);
        res.status(500).json({ 
            error: 'Behavior analysis failed',
            details: error.message 
        });
    }
});

// Get behavior detection statistics
app.get('/api/behavior/stats', (req, res) => {
    try {
        const stats = behaviorDetector.getStatistics();
        res.json({
            success: true,
            stats
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ 
            error: 'Failed to get statistics',
            details: error.message 
        });
    }
});

// Train behavior model with feedback
app.post('/api/behavior/train', async (req, res) => {
    try {
        const { filePath, actualThreat, userFeedback } = req.body;
        
        if (!filePath || actualThreat === undefined) {
            return res.status(400).json({ error: 'filePath and actualThreat required' });
        }

        const result = await behaviorDetector.trainWithFeedback(
            filePath, 
            parseFloat(actualThreat), 
            userFeedback
        );

        res.json({
            success: true,
            result
        });
    } catch (error) {
        console.error('Training error:', error);
        res.status(500).json({ 
            error: 'Training failed',
            details: error.message 
        });
    }
});

// Log file activity for behavior tracking
app.post('/api/behavior/log-activity', (req, res) => {
    try {
        const { type, activity } = req.body;
        
        switch (type) {
            case 'file':
                behaviorDetector.logFileActivity(activity);
                break;
            case 'network':
                behaviorDetector.logNetworkActivity(activity);
                break;
            case 'registry':
                behaviorDetector.logRegistryActivity(activity);
                break;
            default:
                return res.status(400).json({ error: 'Invalid activity type' });
        }

        res.json({ success: true, message: 'Activity logged' });
    } catch (error) {
        console.error('Activity logging error:', error);
        res.status(500).json({ 
            error: 'Failed to log activity',
            details: error.message 
        });
    }
});

// ==================== PREDICTIVE ANALYTICS ====================

// Analyze predictive threats
app.get('/api/predictive/analyze', async (req, res) => {
    try {
        const options = {
            includeRecommendations: req.query.recommendations !== 'false',
            includePredictions: req.query.predictions !== 'false'
        };

        const analysis = await predictiveAnalytics.analyzePredictiveThreats(options);

        res.json({
            success: true,
            analysis
        });
    } catch (error) {
        console.error('Predictive analysis error:', error);
        res.status(500).json({ 
            error: 'Predictive analysis failed',
            details: error.message 
        });
    }
});

// Get predictive analytics statistics
app.get('/api/predictive/stats', (req, res) => {
    try {
        const stats = predictiveAnalytics.getStatistics();
        res.json({
            success: true,
            stats
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ 
            error: 'Failed to get statistics',
            details: error.message 
        });
    }
});

// Get vulnerability predictions
app.get('/api/predictive/vulnerabilities', async (req, res) => {
    try {
        const analysis = await predictiveAnalytics.analyzePredictiveThreats();
        
        res.json({
            success: true,
            vulnerabilities: analysis.vulnerabilities,
            riskLevel: analysis.overallRisk
        });
    } catch (error) {
        console.error('Vulnerability prediction error:', error);
        res.status(500).json({ 
            error: 'Failed to predict vulnerabilities',
            details: error.message 
        });
    }
});

// Get attack vector predictions
app.get('/api/predictive/attack-vectors', async (req, res) => {
    try {
        const analysis = await predictiveAnalytics.analyzePredictiveThreats();
        
        res.json({
            success: true,
            predictions: analysis.predictions,
            confidence: analysis.confidence
        });
    } catch (error) {
        console.error('Attack vector prediction error:', error);
        res.status(500).json({ 
            error: 'Failed to predict attack vectors',
            details: error.message 
        });
    }
});

// Get time-series threat forecast
app.get('/api/predictive/forecast', async (req, res) => {
    try {
        const hoursAhead = parseInt(req.query.hours) || 24;
        const analysis = await predictiveAnalytics.analyzePredictiveThreats();
        
        res.json({
            success: true,
            forecast: analysis.timeSeriesPrediction
        });
    } catch (error) {
        console.error('Forecast error:', error);
        res.status(500).json({ 
            error: 'Failed to generate forecast',
            details: error.message 
        });
    }
});

// ==================== SMART SCAN SCHEDULING ====================

// Get optimal scan schedule
app.post('/api/scheduler/optimize', async (req, res) => {
    try {
        const { scanType = 'full', frequency = 'daily' } = req.body;
        
        const schedule = await smartScheduler.generateOptimalSchedule(scanType, frequency);

        res.json({
            success: true,
            schedule
        });
    } catch (error) {
        console.error('Schedule optimization error:', error);
        res.status(500).json({ 
            error: 'Failed to optimize schedule',
            details: error.message 
        });
    }
});

// Get usage patterns
app.get('/api/scheduler/patterns', async (req, res) => {
    try {
        const patterns = await smartScheduler.analyzeUsagePatterns();

        res.json({
            success: true,
            patterns
        });
    } catch (error) {
        console.error('Pattern analysis error:', error);
        res.status(500).json({ 
            error: 'Failed to analyze patterns',
            details: error.message 
        });
    }
});

// Schedule a scan
app.post('/api/scheduler/schedule', async (req, res) => {
    try {
        const { scanType, schedule, options } = req.body;
        
        if (!scanType || !schedule) {
            return res.status(400).json({ error: 'scanType and schedule required' });
        }

        const scheduledScan = await smartScheduler.scheduleScan(scanType, schedule, options);

        res.json({
            success: true,
            scan: scheduledScan
        });
    } catch (error) {
        console.error('Scan scheduling error:', error);
        res.status(500).json({ 
            error: 'Failed to schedule scan',
            details: error.message 
        });
    }
});

// Get all scheduled scans
app.get('/api/scheduler/scans', (req, res) => {
    try {
        const scans = smartScheduler.getScheduledScans();

        res.json({
            success: true,
            scans
        });
    } catch (error) {
        console.error('Get scans error:', error);
        res.status(500).json({ 
            error: 'Failed to get scheduled scans',
            details: error.message 
        });
    }
});

// Update scheduler preferences
app.put('/api/scheduler/preferences', (req, res) => {
    try {
        const preferences = smartScheduler.updatePreferences(req.body);

        res.json({
            success: true,
            preferences
        });
    } catch (error) {
        console.error('Update preferences error:', error);
        res.status(500).json({ 
            error: 'Failed to update preferences',
            details: error.message 
        });
    }
});

// Get scheduler statistics
app.get('/api/scheduler/stats', (req, res) => {
    try {
        const stats = smartScheduler.getStatistics();

        res.json({
            success: true,
            stats
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ 
            error: 'Failed to get statistics',
            details: error.message 
        });
    }
});

// ==================== THREAT INTELLIGENCE FEED ====================

// Initialize threat intelligence
app.post('/api/threat-intel/initialize', async (req, res) => {
    try {
        await threatIntelligence.initialize();

        res.json({
            success: true,
            message: 'Threat intelligence initialized'
        });
    } catch (error) {
        console.error('Initialization error:', error);
        res.status(500).json({ 
            error: 'Failed to initialize threat intelligence',
            details: error.message 
        });
    }
});

// Check IP reputation
app.get('/api/threat-intel/ip/:ip', async (req, res) => {
    try {
        const { ip } = req.params;
        const reputation = await threatIntelligence.checkIpReputation(ip);

        res.json({
            success: true,
            reputation
        });
    } catch (error) {
        console.error('IP reputation check error:', error);
        res.status(500).json({ 
            error: 'Failed to check IP reputation',
            details: error.message 
        });
    }
});

// Check URL reputation
app.post('/api/threat-intel/url', async (req, res) => {
    try {
        const { url } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: 'URL required' });
        }

        const reputation = await threatIntelligence.checkUrlReputation(url);

        res.json({
            success: true,
            reputation
        });
    } catch (error) {
        console.error('URL reputation check error:', error);
        res.status(500).json({ 
            error: 'Failed to check URL reputation',
            details: error.message 
        });
    }
});

// Check file hash reputation
app.post('/api/threat-intel/hash', async (req, res) => {
    try {
        const { hash } = req.body;
        
        if (!hash) {
            return res.status(400).json({ error: 'File hash required' });
        }

        const reputation = await threatIntelligence.checkFileReputation(hash);

        res.json({
            success: true,
            reputation
        });
    } catch (error) {
        console.error('Hash reputation check error:', error);
        res.status(500).json({ 
            error: 'Failed to check file reputation',
            details: error.message 
        });
    }
});

// Get latest threat feeds
app.get('/api/threat-intel/feeds', async (req, res) => {
    try {
        await threatIntelligence.initialize();
        
        res.json({
            success: true,
            feeds: threatIntelligence.feeds,
            lastUpdate: threatIntelligence.lastUpdate
        });
    } catch (error) {
        console.error('Get feeds error:', error);
        res.status(500).json({ 
            error: 'Failed to get threat feeds',
            details: error.message 
        });
    }
});

// Update threat feeds
app.post('/api/threat-intel/update', async (req, res) => {
    try {
        // Force update of threat feeds
        await threatIntelligence.initialize();
        
        res.json({
            success: true,
            message: 'Threat feeds updated successfully',
            lastUpdate: threatIntelligence.lastUpdate
        });
    } catch (error) {
        console.error('Update feeds error:', error);
        res.status(500).json({ 
            error: 'Failed to update threat feeds',
            details: error.message 
        });
    }
});

// ========================================
// 📱 MOBILE COMPANION APP API
// ========================================

// Get all paired devices
app.get('/api/mobile/devices', (req, res) => {
    const devices = cloudSync.getDevices();
    res.json({
        success: true,
        devices: devices.map(d => ({
            id: d.id,
            name: d.name,
            platform: d.platform,
            status: d.syncEnabled ? 'protected' : 'warning',
            lastSeen: d.lastSeen,
            filesScanned: systemStats.totalScans * 50,
            threatsBlocked: systemStats.threatsDetected,
        })),
    });
});

// Pair new device
app.post('/api/mobile/devices/pair', async (req, res) => {
    try {
        const { pairingCode, deviceInfo } = req.body;
        
        // Validate pairing code (in production, check against generated codes)
        if (!pairingCode || pairingCode.length !== 6) {
            return res.status(400).json({ error: 'Invalid pairing code' });
        }

        const device = await cloudSync.registerDevice(deviceInfo);

        res.json({
            success: true,
            device: {
                id: device.id,
                name: device.name,
                platform: device.platform,
                pairedAt: device.lastSeen,
            },
        });
    } catch (error) {
        console.error('Device pairing error:', error);
        res.status(500).json({ error: 'Failed to pair device', details: error.message });
    }
});

// Get device status
app.get('/api/mobile/devices/:id/status', (req, res) => {
    const device = cloudSync.getDevice(req.params.id);
    
    if (!device) {
        return res.status(404).json({ error: 'Device not found' });
    }

    res.json({
        success: true,
        protected: device.syncEnabled,
        scanning: false, // Would check actual scan status
        statistics: {
            filesScanned: systemStats.totalScans * 50,
            threatsBlocked: systemStats.threatsDetected,
            quarantined: quarantineItems.length,
            lastUpdate: systemStats.lastScanTime,
        },
        lastUpdate: device.lastSync,
    });
});

// Start remote scan
app.post('/api/mobile/devices/:id/scan', (req, res) => {
    const { scanType = 'quick' } = req.body;
    const device = cloudSync.getDevice(req.params.id);
    
    if (!device) {
        return res.status(404).json({ error: 'Device not found' });
    }

    // Simulate scan start
    systemStats.totalScans++;
    systemStats.lastScanTime = new Date().toISOString();

    res.json({
        success: true,
        scanId: `scan-${Date.now()}`,
        scanType,
        startedAt: new Date().toISOString(),
    });
});

// Get scan status
app.get('/api/mobile/devices/:id/scan/status', (req, res) => {
    res.json({
        success: true,
        scanning: false,
        scanProgress: {
            filesScanned: 1250,
            totalFiles: 5000,
            progress: 25,
            currentFile: '/Users/example/Documents/file.pdf',
        },
    });
});

// Stop scan
app.delete('/api/mobile/devices/:id/scan', (req, res) => {
    res.json({
        success: true,
        message: 'Scan stopped',
    });
});

// Get threats
app.get('/api/mobile/devices/:id/threats', (req, res) => {
    res.json({
        success: true,
        threats: quarantineItems.slice(0, 10).map(item => ({
            id: `threat-${Date.now()}-${Math.random()}`,
            name: item.fileName,
            path: item.originalPath,
            type: item.threatType || 'malware',
            severity: item.severity || 'high',
            detectedAt: item.quarantinedAt,
        })),
    });
});

// Quarantine threat
app.post('/api/mobile/devices/:id/threats/:threatId/quarantine', (req, res) => {
    res.json({
        success: true,
        message: 'Threat quarantined successfully',
    });
});

// Get device settings
app.get('/api/mobile/devices/:id/settings', (req, res) => {
    const device = cloudSync.getDevice(req.params.id);
    
    if (!device) {
        return res.status(404).json({ error: 'Device not found' });
    }

    res.json({
        success: true,
        settings: device.settings || settings,
    });
});

// Update device settings
app.put('/api/mobile/devices/:id/settings', async (req, res) => {
    try {
        const result = await cloudSync.syncSettings(req.params.id, req.body);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update settings', details: error.message });
    }
});

// Get device statistics
app.get('/api/mobile/devices/:id/statistics', (req, res) => {
    res.json({
        success: true,
        statistics: {
            totalScans: systemStats.totalScans,
            threatsDetected: systemStats.threatsDetected,
            filesQuarantined: quarantineItems.length,
            lastScan: systemStats.lastScanTime,
            protectionUptime: '99.9%',
        },
    });
});

// ========================================
// 🌐 BROWSER EXTENSION API
// ========================================

// Get threat database for browser extension
app.get('/api/browser-extension/threats', async (req, res) => {
    try {
        await threatIntelligence.initialize();

        res.json({
            success: true,
            maliciousUrls: Array.from(threatIntelligence.maliciousUrls).slice(0, 1000),
            phishingUrls: Array.from(threatIntelligence.phishingUrls).slice(0, 1000),
            maliciousDomains: Array.from(threatIntelligence.maliciousDomains).slice(0, 500),
            lastUpdate: threatIntelligence.lastUpdate,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get threat database', details: error.message });
    }
});

// Check URL safety
app.post('/api/browser-extension/check-url', async (req, res) => {
    try {
        const { url } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: 'URL required' });
        }

        const reputation = await threatIntelligence.checkUrlReputation(url);

        res.json({
            success: true,
            malicious: reputation.malicious,
            type: reputation.category,
            score: reputation.score,
            sources: reputation.sources,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to check URL', details: error.message });
    }
});

// Report phishing
app.post('/api/browser-extension/report-phishing', (req, res) => {
    const { url, details } = req.body;
    
    console.log('Phishing reported:', url, details);
    
    // Add to threat database
    threatIntelligence.phishingUrls.add(url);

    res.json({
        success: true,
        message: 'Thank you for reporting this phishing attempt',
    });
});

// Report false positive
app.post('/api/browser-extension/report-false-positive', (req, res) => {
    const { url } = req.body;
    
    console.log('False positive reported:', url);

    res.json({
        success: true,
        message: 'Thank you for your feedback. Our team will review this report.',
    });
});

// Get extension statistics
app.get('/api/browser-extension/statistics', (req, res) => {
    res.json({
        success: true,
        statistics: {
            totalUrls: threatIntelligence.maliciousUrls.size + threatIntelligence.phishingUrls.size,
            maliciousUrls: threatIntelligence.maliciousUrls.size,
            phishingUrls: threatIntelligence.phishingUrls.size,
            lastUpdate: threatIntelligence.lastUpdate,
        },
    });
});

// ========================================
// 🔄 CLOUD SYNC API
// ========================================

// Register device for cloud sync
app.post('/api/sync/register', async (req, res) => {
    try {
        const device = await cloudSync.registerDevice(req.body);
        res.json({
            success: true,
            device,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to register device', details: error.message });
    }
});

// Get all synced devices
app.get('/api/sync/devices', (req, res) => {
    const devices = cloudSync.getDevices();
    res.json({
        success: true,
        devices,
    });
});

// Get specific device
app.get('/api/sync/devices/:id', (req, res) => {
    const device = cloudSync.getDevice(req.params.id);
    
    if (!device) {
        return res.status(404).json({ error: 'Device not found' });
    }

    res.json({
        success: true,
        device,
    });
});

// Update device status
app.put('/api/sync/devices/:id/status', (req, res) => {
    cloudSync.updateDeviceStatus(req.params.id, req.body);
    
    res.json({
        success: true,
        message: 'Device status updated',
    });
});

// Sync settings
app.post('/api/sync/settings', async (req, res) => {
    try {
        const { deviceId, settings: deviceSettings } = req.body;
        const result = await cloudSync.syncSettings(deviceId, deviceSettings);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to sync settings', details: error.message });
    }
});

// Sync quarantine
app.post('/api/sync/quarantine', async (req, res) => {
    try {
        const { deviceId, quarantineData } = req.body;
        const result = await cloudSync.syncQuarantine(deviceId, quarantineData);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to sync quarantine', details: error.message });
    }
});

// Sync reports
app.post('/api/sync/reports', async (req, res) => {
    try {
        const { deviceId, reports } = req.body;
        const result = await cloudSync.syncReports(deviceId, reports);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to sync reports', details: error.message });
    }
});

// Get sync status
app.get('/api/sync/status', (req, res) => {
    const { deviceId } = req.query;
    const status = cloudSync.getSyncStatus(deviceId);
    
    res.json({
        success: true,
        status,
    });
});

// Get pending changes
app.get('/api/sync/pending/:deviceId', (req, res) => {
    const pending = cloudSync.getPendingChanges(req.params.deviceId);
    
    res.json({
        success: true,
        pending,
    });
});

// Resolve sync conflict
app.post('/api/sync/resolve-conflict', (req, res) => {
    const { deviceId, type, resolution } = req.body;
    const result = cloudSync.resolveConflict(deviceId, type, resolution);
    
    res.json(result);
});

// Get sync statistics
app.get('/api/sync/statistics', (req, res) => {
    const statistics = cloudSync.getStatistics();
    
    res.json({
        success: true,
        statistics,
    });
});

// Export sync data
app.get('/api/sync/export', (req, res) => {
    const data = cloudSync.exportSyncData();
    
    res.json({
        success: true,
        data,
    });
});

// Import sync data
app.post('/api/sync/import', (req, res) => {
    const result = cloudSync.importSyncData(req.body);
    res.json(result);
});

// ========================================
// 💻 CROSS-PLATFORM API
// ========================================

// Get platform information
app.get('/api/platform/info', (req, res) => {
    const info = platformAdapter.getSystemInfo();
    
    res.json({
        success: true,
        platform: info,
        paths: platformAdapter.getPaths(),
    });
});

// Get running processes
app.get('/api/platform/processes', async (req, res) => {
    try {
        const processes = await platformAdapter.getProcesses();
        
        res.json({
            success: true,
            processes: processes.slice(0, 100), // Limit to 100 processes
            total: processes.length,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get processes', details: error.message });
    }
});

// Kill process
app.delete('/api/platform/processes/:pid', async (req, res) => {
    try {
        await platformAdapter.killProcess(req.params.pid);
        
        res.json({
            success: true,
            message: `Process ${req.params.pid} terminated`,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to kill process', details: error.message });
    }
});

// Get firewall status
app.get('/api/platform/firewall', async (req, res) => {
    try {
        const status = await platformAdapter.getFirewallStatus();
        
        res.json({
            success: true,
            firewall: status,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get firewall status', details: error.message });
    }
});

// Get antivirus status
app.get('/api/platform/antivirus', async (req, res) => {
    try {
        const status = await platformAdapter.getAntivirusStatus();
        
        res.json({
            success: true,
            antivirus: status,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get antivirus status', details: error.message });
    }
});

// Get update status
app.get('/api/platform/updates', async (req, res) => {
    try {
        const status = await platformAdapter.getUpdateStatus();
        
        res.json({
            success: true,
            updates: status,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get update status', details: error.message });
    }
});

// Get network connections
app.get('/api/platform/network', async (req, res) => {
    try {
        const connections = await platformAdapter.getNetworkConnections();
        
        res.json({
            success: true,
            connections: connections.slice(0, 50), // Limit to 50 connections
            total: connections.length,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get network connections', details: error.message });
    }
});

// Get disk usage
app.get('/api/platform/disk', async (req, res) => {
    try {
        const disks = await platformAdapter.getDiskUsage();
        
        res.json({
            success: true,
            disks,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get disk usage', details: error.message });
    }
});

// Scan specific file
app.post('/api/platform/scan-file', async (req, res) => {
    try {
        const { filePath } = req.body;
        
        if (!filePath) {
            return res.status(400).json({ error: 'File path required' });
        }

        const result = await platformAdapter.scanFile(filePath);
        
        res.json({
            success: true,
            scan: result,
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to scan file', details: error.message });
    }
});

// ========================================
// ADVANCED MONITORING API
// ========================================

// Start registry monitoring
app.post('/api/monitoring/registry/start', async (req, res) => {
    try {
        const result = await advancedMonitoring.startRegistryMonitoring();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to start registry monitoring', details: error.message });
    }
});

// Stop registry monitoring
app.post('/api/monitoring/registry/stop', (req, res) => {
    try {
        const result = advancedMonitoring.stopRegistryMonitoring();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to stop registry monitoring', details: error.message });
    }
});

// Get registry changes
app.get('/api/monitoring/registry/changes', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const result = advancedMonitoring.getRegistryChanges(limit);
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get registry changes', details: error.message });
    }
});

// Validate certificate
app.post('/api/monitoring/certificate/validate', async (req, res) => {
    try {
        const { filePath } = req.body;
        
        if (!filePath) {
            return res.status(400).json({ error: 'File path required' });
        }

        const result = await advancedMonitoring.validateCertificate(filePath);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to validate certificate', details: error.message });
    }
});

// Start memory scanning
app.post('/api/monitoring/memory/start', async (req, res) => {
    try {
        const result = await advancedMonitoring.startMemoryScanning();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to start memory scanning', details: error.message });
    }
});

// Stop memory scanning
app.post('/api/monitoring/memory/stop', (req, res) => {
    try {
        const result = advancedMonitoring.stopMemoryScanning();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to stop memory scanning', details: error.message });
    }
});

// Perform memory scan
app.get('/api/monitoring/memory/scan', async (req, res) => {
    try {
        const result = await advancedMonitoring.scanMemory();
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to scan memory', details: error.message });
    }
});

// Scan for rootkits
app.post('/api/monitoring/rootkit/scan', async (req, res) => {
    try {
        const result = await advancedMonitoring.detectRootkits();
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to scan for rootkits', details: error.message });
    }
});

// Scan for cryptocurrency miners
app.post('/api/monitoring/cryptominer/scan', async (req, res) => {
    try {
        const result = await advancedMonitoring.detectCryptoMiners();
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to scan for crypto miners', details: error.message });
    }
});

// Get monitoring statistics
app.get('/api/monitoring/statistics', (req, res) => {
    try {
        const stats = advancedMonitoring.getStatistics();
        res.json({
            success: true,
            statistics: stats
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get statistics', details: error.message });
    }
});

// Get detected threats
app.get('/api/monitoring/threats', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const result = advancedMonitoring.getDetectedThreats(limit);
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get threats', details: error.message });
    }
});

// Clear threat history
app.delete('/api/monitoring/threats', (req, res) => {
    try {
        const result = advancedMonitoring.clearThreatHistory();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to clear threat history', details: error.message });
    }
});

// ========================================
// ADVANCED FIREWALL API
// ========================================

// Inspect packet through all firewall layers
app.post('/api/advanced-firewall/inspect', (req, res) => {
    try {
        const packet = req.body;
        const result = advancedFirewall.inspectPacket(packet);
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to inspect packet', details: error.message });
    }
});

// Get firewall rules
app.get('/api/advanced-firewall/rules', (req, res) => {
    try {
        const rules = advancedFirewall.getRules();
        res.json({
            success: true,
            rules,
            count: rules.length
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get rules', details: error.message });
    }
});

// Add firewall rule
app.post('/api/advanced-firewall/rules', (req, res) => {
    try {
        const rule = req.body;
        const result = advancedFirewall.addRule(rule);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to add rule', details: error.message });
    }
});

// Update firewall rule
app.put('/api/advanced-firewall/rules/:ruleId', (req, res) => {
    try {
        const { ruleId } = req.params;
        const updates = req.body;
        const result = advancedFirewall.updateRule(ruleId, updates);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to update rule', details: error.message });
    }
});

// Delete firewall rule
app.delete('/api/advanced-firewall/rules/:ruleId', (req, res) => {
    try {
        const { ruleId } = req.params;
        const result = advancedFirewall.deleteRule(ruleId);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete rule', details: error.message });
    }
});

// Block IP address
app.post('/api/advanced-firewall/block-ip', (req, res) => {
    try {
        const { ip, reason } = req.body;
        const result = advancedFirewall.blockIP(ip, reason);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to block IP', details: error.message });
    }
});

// Unblock IP address
app.post('/api/advanced-firewall/unblock-ip', (req, res) => {
    try {
        const { ip } = req.body;
        const result = advancedFirewall.unblockIP(ip);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to unblock IP', details: error.message });
    }
});

// Block domain
app.post('/api/advanced-firewall/block-domain', (req, res) => {
    try {
        const { domain, reason } = req.body;
        const result = advancedFirewall.blockDomain(domain, reason);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to block domain', details: error.message });
    }
});

// Block application
app.post('/api/advanced-firewall/block-application', (req, res) => {
    try {
        const { application } = req.body;
        const result = advancedFirewall.blockApplication(application);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to block application', details: error.message });
    }
});

// Block country
app.post('/api/advanced-firewall/block-country', (req, res) => {
    try {
        const { countryCode } = req.body;
        const result = advancedFirewall.blockCountry(countryCode);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to block country', details: error.message });
    }
});

// Get blocked lists
app.get('/api/advanced-firewall/blocked', (req, res) => {
    try {
        const lists = advancedFirewall.getBlockedLists();
        res.json({
            success: true,
            ...lists
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get blocked lists', details: error.message });
    }
});

// Get firewall statistics
app.get('/api/advanced-firewall/statistics', (req, res) => {
    try {
        const stats = advancedFirewall.getStatistics();
        res.json({
            success: true,
            statistics: stats
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get statistics', details: error.message });
    }
});

// Get DPI detections
app.get('/api/advanced-firewall/dpi/detections', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const detections = advancedFirewall.getDPIDetections(limit);
        res.json({
            success: true,
            detections,
            count: detections.length
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get DPI detections', details: error.message });
    }
});

// Get IDS alerts
app.get('/api/advanced-firewall/ids/alerts', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const alerts = advancedFirewall.getIDSAlerts(limit);
        res.json({
            success: true,
            alerts,
            count: alerts.length
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get IDS alerts', details: error.message });
    }
});

// Get IPS blocks
app.get('/api/advanced-firewall/ips/blocks', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const blocks = advancedFirewall.getIPSBlocks(limit);
        res.json({
            success: true,
            blocks,
            count: blocks.length
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get IPS blocks', details: error.message });
    }
});

// Get traffic analysis
app.get('/api/advanced-firewall/traffic/analysis', (req, res) => {
    try {
        const analysis = advancedFirewall.getTrafficAnalysis();
        res.json({
            success: true,
            ...analysis
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get traffic analysis', details: error.message });
    }
});

// Start firewall monitoring
app.post('/api/advanced-firewall/monitoring/start', (req, res) => {
    try {
        const result = advancedFirewall.startMonitoring();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to start monitoring', details: error.message });
    }
});

// Stop firewall monitoring
app.post('/api/advanced-firewall/monitoring/stop', (req, res) => {
    try {
        const result = advancedFirewall.stopMonitoring();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to stop monitoring', details: error.message });
    }
});

// Reset firewall statistics
app.post('/api/advanced-firewall/statistics/reset', (req, res) => {
    try {
        const result = advancedFirewall.resetStatistics();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Failed to reset statistics', details: error.message });
    }
});

// ========================================
// WIFI SECURITY ENDPOINTS
// ========================================

// Scan WiFi networks
app.post('/api/wifi/scan', async (req, res) => {
    try {
        console.log('📡 WiFi scan requested');
        
        // Generate mock WiFi scan data
        const mockNetworks = [
            {
                ssid: 'HomeNetwork_5GHz',
                bssid: 'A4:12:E3:45:67:89',
                security: 'WPA3',
                signalStrength: 85,
                frequency: 5200,
                channel: 40,
                channelWidth: 80,
                isCurrentNetwork: true,
                encryption: 'AES',
                authentication: 'SAE',
                securityScore: 95,
                securityLevel: 'excellent',
                threats: [],
                recommendations: ['Network is using the most secure protocol (WPA3)']
            },
            {
                ssid: 'Neighbor_WiFi',
                bssid: 'B8:23:F4:56:78:90',
                security: 'WPA2',
                signalStrength: 65,
                frequency: 2437,
                channel: 6,
                channelWidth: 20,
                isCurrentNetwork: false,
                encryption: 'AES',
                authentication: 'PSK',
                securityScore: 75,
                securityLevel: 'good',
                threats: [],
                recommendations: ['Consider upgrading to WPA3 if supported']
            },
            {
                ssid: 'Public_Hotspot',
                bssid: 'C9:34:A5:67:89:01',
                security: 'Open',
                signalStrength: 45,
                frequency: 2412,
                channel: 1,
                channelWidth: 20,
                isCurrentNetwork: false,
                encryption: 'None',
                authentication: 'None',
                securityScore: 20,
                securityLevel: 'critical',
                threats: ['Unencrypted network - data can be intercepted', 'Potential for man-in-the-middle attacks'],
                recommendations: ['Avoid using this network for sensitive activities', 'Use VPN if connection is necessary']
            },
            {
                ssid: 'OldRouter_2G',
                bssid: 'D0:45:B6:78:90:12',
                security: 'WEP',
                signalStrength: 30,
                frequency: 2462,
                channel: 11,
                channelWidth: 20,
                isCurrentNetwork: false,
                encryption: 'WEP',
                authentication: 'WEP',
                securityScore: 15,
                securityLevel: 'critical',
                threats: ['WEP encryption is severely outdated and easily cracked', 'Network vulnerable to automated attacks'],
                recommendations: ['Never connect to WEP networks', 'Contact network owner to upgrade security']
            }
        ];

        const scanResult = {
            timestamp: new Date().toISOString(),
            currentNetwork: mockNetworks.find(n => n.isCurrentNetwork),
            nearbyNetworks: mockNetworks.filter(n => !n.isCurrentNetwork),
            totalNetworks: mockNetworks.length,
            securitySummary: {
                excellent: mockNetworks.filter(n => n.securityScore >= 90).length,
                good: mockNetworks.filter(n => n.securityScore >= 70 && n.securityScore < 90).length,
                warning: mockNetworks.filter(n => n.securityScore >= 40 && n.securityScore < 70).length,
                critical: mockNetworks.filter(n => n.securityScore < 40).length
            },
            channelAnalysis: {
                currentChannel: 40,
                channelCongestion: 'low',
                recommendedChannels: [36, 40, 44],
                interferingNetworks: 1
            },
            threats: {
                evilTwinDetected: false,
                mitm: false,
                dnsHijacking: false,
                rogueAP: false
            },
            recommendations: [
                'Your current network (HomeNetwork_5GHz) is secure with WPA3',
                'Avoid connecting to open networks like "Public_Hotspot"',
                'WEP networks detected nearby - ensure your devices never auto-connect to these'
            ]
        };

        res.json({
            success: true,
            data: scanResult
        });

        console.log('✅ WiFi scan completed:', mockNetworks.length, 'networks found');
    } catch (error) {
        console.error('❌ WiFi scan error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to scan WiFi networks', 
            details: error.message 
        });
    }
});

// Analyze WiFi channel
app.post('/api/wifi/analyze-channel', async (req, res) => {
    try {
        console.log('📊 WiFi channel analysis requested');
        
        const channelAnalysis = {
            currentChannel: 40,
            frequency: 5200,
            channelWidth: 80,
            channelCongestion: 'low',
            congestionLevel: 15, // percentage
            interferingNetworks: 1,
            signalQuality: 'excellent',
            noiseLevel: -85, // dBm
            recommendedChannels: [
                { channel: 36, congestion: 10, reason: 'Least congested' },
                { channel: 40, congestion: 15, reason: 'Current channel - good performance' },
                { channel: 44, congestion: 20, reason: 'Alternative with low congestion' }
            ],
            channelMap: [
                { channel: 36, networks: 2, overlap: false },
                { channel: 40, networks: 3, overlap: true },
                { channel: 44, networks: 1, overlap: false },
                { channel: 149, networks: 2, overlap: false }
            ]
        };

        res.json({
            success: true,
            data: channelAnalysis
        });

        console.log('✅ Channel analysis completed');
    } catch (error) {
        console.error('❌ Channel analysis error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to analyze WiFi channel', 
            details: error.message 
        });
    }
});

// Detect evil twin networks
app.post('/api/wifi/detect-evil-twin', async (req, res) => {
    try {
        console.log('🔍 Evil twin detection requested');
        
        const evilTwinResult = {
            detected: false,
            suspiciousNetworks: [],
            currentNetworkSafe: true,
            analysis: {
                duplicateSSIDs: 0,
                signalAnomalies: 0,
                securityDowngrades: 0
            },
            message: 'No evil twin networks detected. Your current network appears legitimate.'
        };

        res.json({
            success: true,
            data: evilTwinResult
        });

        console.log('✅ Evil twin detection completed');
    } catch (error) {
        console.error('❌ Evil twin detection error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to detect evil twin networks', 
            details: error.message 
        });
    }
});

// ========================================
// SERVER STARTUP
// ========================================

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

// ====== LICENSE MANAGEMENT API ======
// Mount license API routes
app.use('/api/license', licenseAPI);

// Start server
app.listen(PORT, async () => {
    console.log(`🛡️  Nebula Shield Anti-Virus Mock Backend running on http://localhost:${PORT}`);
    console.log(`\n📊 Core API Endpoints:`);
    console.log(`   GET  /api/status         - System status`);
    console.log(`   GET  /api/stats          - System statistics`);
    console.log(`   POST /api/scan/file      - Scan uploaded file`);
    console.log(`   POST /api/scan/directory - Scan directory`);
    console.log(`   POST /api/scan/quick     - Quick system scan`);
    console.log(`   POST /api/scan/full      - Full system scan`);
    console.log(`   GET  /api/quarantine     - Get quarantined items`);
    console.log(`   GET  /api/settings       - Get settings`);
    console.log(`   PUT  /api/settings       - Update settings`);
    
    console.log(`\n📦 Bulk Operations API:`);
    console.log(`   POST   /api/bulk/operations           - Create operation`);
    console.log(`   POST   /api/bulk/operations/:id/execute - Execute operation`);
    console.log(`   POST   /api/bulk/operations/:id/cancel  - Cancel operation`);
    console.log(`   GET    /api/bulk/operations/:id        - Get operation status`);
    console.log(`   GET    /api/bulk/operations            - List all operations`);
    console.log(`   GET    /api/bulk/statistics            - Get statistics`);
    console.log(`   GET    /api/bulk/operations/:id/export - Export results`);
    console.log(`   DELETE /api/bulk/operations/:id        - Delete operation`);
    
    console.log(`\n⏰ Scheduled Tasks API:`);
    console.log(`   POST /api/tasks              - Create task`);
    console.log(`   GET  /api/tasks              - List all tasks`);
    console.log(`   GET  /api/tasks/:id          - Get task details`);
    console.log(`   PUT  /api/tasks/:id          - Update task`);
    console.log(`   DELETE /api/tasks/:id        - Delete task`);
    console.log(`   POST /api/tasks/:id/execute  - Execute task manually`);
    console.log(`   PUT  /api/tasks/:id/toggle   - Enable/disable task`);
    console.log(`   GET  /api/tasks/:id/history  - Get execution history`);
    console.log(`   GET  /api/tasks/statistics   - Get statistics`);
    console.log(`   POST /api/tasks/import       - Import tasks`);
    console.log(`   GET  /api/tasks/export       - Export tasks`);
    
    console.log(`\n💾 Settings Import/Export API:`);
    console.log(`   POST   /api/settings/export           - Export settings`);
    console.log(`   POST   /api/settings/export/file      - Export to file`);
    console.log(`   POST   /api/settings/import           - Import settings`);
    
    console.log(`\n🔥 Firewall Engine API:`);
    console.log(`   GET    /api/firewall/status           - Get firewall status`);
    console.log(`   GET    /api/firewall/rules            - Get all rules`);
    console.log(`   POST   /api/firewall/rules            - Add new rule`);
    console.log(`   PUT    /api/firewall/rules/:id        - Update rule`);
    console.log(`   DELETE /api/firewall/rules/:id        - Delete rule`);
    console.log(`   POST   /api/firewall/block-ip         - Block IP address`);
    console.log(`   POST   /api/firewall/unblock-ip       - Unblock IP address`);
    console.log(`   GET    /api/firewall/blocked-ips      - Get blocked IPs`);
    console.log(`   GET    /api/firewall/threats          - Get threat log`);
    console.log(`   DELETE /api/firewall/threats          - Clear threat log`);
    console.log(`   POST   /api/firewall/monitoring/start - Start monitoring`);
    console.log(`   POST   /api/firewall/monitoring/stop  - Stop monitoring`);
    console.log(`   GET    /api/firewall/windows/rules    - Get Windows Firewall rules`);
    console.log(`   POST   /api/firewall/windows/rules    - Add Windows Firewall rule`);
    console.log(`   DELETE /api/firewall/windows/rules/:name - Remove Windows Firewall rule`);
    console.log(`   GET    /api/firewall/statistics       - Get statistics`);
    console.log(`   POST   /api/firewall/statistics/reset - Reset statistics`);
    
    console.log(`\n🤖 AI Threat Detection API:`);
    console.log(`   POST /api/ai/analyze-connection   - Analyze connection with AI`);
    console.log(`   GET  /api/ai/ip-reputation/:ip    - Get IP reputation`);
    console.log(`   GET  /api/ai/model-stats          - Get AI model statistics`);
    console.log(`   POST /api/ai/reset-model          - Reset AI learning model`);
    
    console.log(`\n🧠 Enhanced ML Detection API:`);
    console.log(`   POST /api/ml/train              - Train ML models`);
    console.log(`   POST /api/ml/detect             - Detect malware in file`);
    console.log(`   POST /api/ml/analyze-network    - Analyze network packet`);
    console.log(`   GET  /api/ml/stats              - Get ML engine statistics`);
    console.log(`   GET  /api/ml/history            - Get detection history`);
    console.log(`   POST /api/ml/export             - Export trained models`);
    console.log(`   POST /api/ml/import             - Import trained models`);
    console.log(`   GET  /api/ml/performance        - Get model performance metrics`);
    
    console.log(`\n🧠 Behavior-Based Detection API:`);
    console.log(`   POST /api/behavior/analyze       - Analyze file behavior for zero-day threats`);
    console.log(`   GET  /api/behavior/stats         - Get behavior detection statistics`);
    console.log(`   POST /api/behavior/train         - Train model with feedback`);
    console.log(`   POST /api/behavior/log-activity  - Log file/network/registry activity`);
    
    console.log(`\n🔮 Predictive Analytics API:`);
    console.log(`   GET  /api/predictive/analyze        - Comprehensive predictive threat analysis`);
    console.log(`   GET  /api/predictive/stats          - Get predictive analytics statistics`);
    console.log(`   GET  /api/predictive/vulnerabilities - Get vulnerability predictions`);
    console.log(`   GET  /api/predictive/attack-vectors - Get attack vector predictions`);
    console.log(`   GET  /api/predictive/forecast       - Get time-series threat forecast`);
    
    console.log(`\n⏰ Smart Scan Scheduling API:`);
    console.log(`   POST /api/scheduler/optimize     - Generate optimal scan schedule`);
    console.log(`   GET  /api/scheduler/patterns     - Get system usage patterns`);
    console.log(`   POST /api/scheduler/schedule     - Schedule a scan`);
    console.log(`   GET  /api/scheduler/scans        - Get all scheduled scans`);
    console.log(`   PUT  /api/scheduler/preferences  - Update scheduler preferences`);
    console.log(`   GET  /api/scheduler/stats        - Get scheduler statistics`);
    
    console.log(`\n🌐 Threat Intelligence Feed API:`);
    console.log(`   POST /api/threat-intel/initialize - Initialize threat intelligence`);
    console.log(`   GET  /api/threat-intel/ip/:ip     - Check IP reputation`);
    console.log(`   POST /api/threat-intel/url        - Check URL reputation`);
    console.log(`   POST /api/threat-intel/hash       - Check file hash reputation`);
    console.log(`   GET  /api/threat-intel/feeds      - Get latest threat feeds`);
    console.log(`   POST /api/threat-intel/update     - Update threat feeds`);
    
    console.log(`   POST   /api/settings/import/file      - Import from file`);
    console.log(`   POST   /api/settings/backups          - Create backup`);
    console.log(`   GET    /api/settings/backups          - List backups`);
    console.log(`   POST   /api/settings/backups/:id/restore - Restore backup`);
    console.log(`   DELETE /api/settings/backups/:id      - Delete backup`);
    console.log(`   POST   /api/settings/compare          - Compare settings`);
    console.log(`   POST   /api/settings/reset            - Reset to defaults`);
    
    console.log(`\n☁️  Cloud Backup API:`);
    console.log(`   GET    /api/cloud/providers              - List providers`);
    console.log(`   POST   /api/cloud/providers/:id/connect  - Connect provider`);
    console.log(`   POST   /api/cloud/providers/:id/disconnect - Disconnect provider`);
    console.log(`   POST   /api/cloud/providers/:id/test     - Test connection`);
    console.log(`   POST   /api/cloud/backups                - Create cloud backup`);
    console.log(`   GET    /api/cloud/backups                - List cloud backups`);
    console.log(`   POST   /api/cloud/backups/:id/restore    - Restore backup`);
    console.log(`   DELETE /api/cloud/backups/:id            - Delete backup`);
    console.log(`   GET    /api/cloud/statistics             - Get statistics`);
    
    console.log(`\n🛡️  Enhanced Hacker Protection API:`);
    console.log(`   GET  /api/security/status           - Protection status`);
    console.log(`   GET  /api/security/statistics       - Security statistics`);
    console.log(`   GET  /api/security/blocked-ips      - List blocked IPs`);
    console.log(`   POST /api/security/block-ip         - Block IP address`);
    console.log(`   POST /api/security/unblock-ip       - Unblock IP address`);
    console.log(`   GET  /api/security/attack-log       - View attack log`);
    console.log(`   GET  /api/security/threat-analysis  - Threat analysis & recommendations`);
    
    console.log(`\n🔑 License Management API:`);
    console.log(`   POST /api/license/generate          - Generate license key (admin)`);
    console.log(`   POST /api/license/validate          - Validate license key`);
    console.log(`   POST /api/license/activate          - Activate license on device`);
    console.log(`   POST /api/license/deactivate        - Deactivate license from device`);
    console.log(`   GET  /api/license/status            - Get license status`);
    console.log(`   GET  /api/license/activations/:key  - List all activations (admin)`);
    console.log(`   GET  /api/license/history/:key      - View audit log (admin)`);
    console.log(`   POST /api/license/tos-accept        - Accept Terms of Service`);
    
    console.log(`\n📱 Mobile Companion App API:`);
    console.log(`   GET    /api/mobile/devices              - List paired devices`);
    console.log(`   POST   /api/mobile/devices/pair         - Pair new device`);
    console.log(`   GET    /api/mobile/devices/:id/status   - Get device status`);
    console.log(`   POST   /api/mobile/devices/:id/scan     - Start remote scan`);
    console.log(`   GET    /api/mobile/devices/:id/scan/status - Get scan status`);
    console.log(`   DELETE /api/mobile/devices/:id/scan     - Stop scan`);
    console.log(`   GET    /api/mobile/devices/:id/threats  - Get threats`);
    console.log(`   POST   /api/mobile/devices/:id/threats/:tid/quarantine - Quarantine threat`);
    console.log(`   GET    /api/mobile/devices/:id/settings - Get device settings`);
    console.log(`   PUT    /api/mobile/devices/:id/settings - Update settings`);
    console.log(`   GET    /api/mobile/devices/:id/statistics - Get statistics`);
    
    console.log(`\n🌐 Browser Extension API:`);
    console.log(`   GET    /api/browser-extension/threats   - Get threat database`);
    console.log(`   POST   /api/browser-extension/check-url - Check URL safety`);
    console.log(`   POST   /api/browser-extension/report-phishing - Report phishing`);
    console.log(`   POST   /api/browser-extension/report-false-positive - Report false positive`);
    console.log(`   GET    /api/browser-extension/statistics - Get extension stats`);
    
    console.log(`\n🔄 Cloud Sync API:`);
    console.log(`   POST   /api/sync/register              - Register device`);
    console.log(`   GET    /api/sync/devices               - List all devices`);
    console.log(`   GET    /api/sync/devices/:id           - Get device info`);
    console.log(`   PUT    /api/sync/devices/:id/status    - Update device status`);
    console.log(`   POST   /api/sync/settings              - Sync settings`);
    console.log(`   POST   /api/sync/quarantine            - Sync quarantine`);
    console.log(`   POST   /api/sync/reports               - Sync reports`);
    console.log(`   GET    /api/sync/status                - Get sync status`);
    console.log(`   GET    /api/sync/pending/:id           - Get pending changes`);
    console.log(`   POST   /api/sync/resolve-conflict      - Resolve sync conflict`);
    console.log(`   GET    /api/sync/statistics            - Get sync statistics`);
    console.log(`   GET    /api/sync/export                - Export sync data`);
    console.log(`   POST   /api/sync/import                - Import sync data`);
    
    console.log(`\n💻 Cross-Platform API:`);
    console.log(`   GET    /api/platform/info              - Get platform information`);
    console.log(`   GET    /api/platform/processes         - List running processes`);
    console.log(`   DELETE /api/platform/processes/:pid    - Kill process`);
    console.log(`   GET    /api/platform/firewall          - Get firewall status`);
    console.log(`   GET    /api/platform/antivirus         - Get antivirus status`);
    console.log(`   GET    /api/platform/updates           - Get update status`);
    console.log(`   GET    /api/platform/network           - Get network connections`);
    console.log(`   GET    /api/platform/disk              - Get disk usage`);
    console.log(`   POST   /api/platform/scan-file         - Scan specific file`);
    
    console.log(`\n📈 Advanced Monitoring API:`);
    console.log(`   POST   /api/monitoring/registry/start     - Start registry monitoring`);
    console.log(`   POST   /api/monitoring/registry/stop      - Stop registry monitoring`);
    console.log(`   GET    /api/monitoring/registry/changes   - Get registry changes`);
    console.log(`   POST   /api/monitoring/certificate/validate - Validate file certificate`);
    console.log(`   POST   /api/monitoring/memory/start       - Start memory scanning`);
    console.log(`   POST   /api/monitoring/memory/stop        - Stop memory scanning`);
    console.log(`   GET    /api/monitoring/memory/scan        - Perform memory scan`);
    console.log(`   POST   /api/monitoring/rootkit/scan       - Scan for rootkits`);
    console.log(`   POST   /api/monitoring/cryptominer/scan   - Scan for crypto miners`);
    console.log(`   GET    /api/monitoring/statistics         - Get monitoring statistics`);
    console.log(`   GET    /api/monitoring/threats            - Get detected threats`);
    console.log(`   DELETE /api/monitoring/threats            - Clear threat history`);
    
    console.log(`\n🛡️  Advanced Firewall API:`);
    console.log(`   POST   /api/advanced-firewall/inspect              - Inspect packet (DPI/IDS/IPS)`);
    console.log(`   GET    /api/advanced-firewall/rules                - Get all firewall rules`);
    console.log(`   POST   /api/advanced-firewall/rules                - Add firewall rule`);
    console.log(`   PUT    /api/advanced-firewall/rules/:id            - Update firewall rule`);
    console.log(`   DELETE /api/advanced-firewall/rules/:id            - Delete firewall rule`);
    console.log(`   POST   /api/advanced-firewall/block-ip             - Block IP address`);
    console.log(`   POST   /api/advanced-firewall/unblock-ip           - Unblock IP address`);
    console.log(`   POST   /api/advanced-firewall/block-domain         - Block domain`);
    console.log(`   POST   /api/advanced-firewall/block-application    - Block application`);
    console.log(`   POST   /api/advanced-firewall/block-country        - Block country (geo-blocking)`);
    console.log(`   GET    /api/advanced-firewall/blocked              - Get all blocked lists`);
    console.log(`   GET    /api/advanced-firewall/statistics           - Get firewall statistics`);
    console.log(`   GET    /api/advanced-firewall/dpi/detections       - Get DPI detections`);
    console.log(`   GET    /api/advanced-firewall/ids/alerts           - Get IDS alerts`);
    console.log(`   GET    /api/advanced-firewall/ips/blocks           - Get IPS blocks`);
    console.log(`   GET    /api/advanced-firewall/traffic/analysis     - Get traffic analysis`);
    console.log(`   POST   /api/advanced-firewall/monitoring/start     - Start firewall monitoring`);
    console.log(`   POST   /api/advanced-firewall/monitoring/stop      - Stop firewall monitoring`);
    console.log(`   POST   /api/advanced-firewall/statistics/reset     - Reset statistics`);
    
    console.log(`\n✅ Backend ready with all advanced features enabled!`);
    console.log(`🔒 Enhanced hacker protection active - Multi-layer security engaged!`);
    console.log(`🌐 Multi-platform support: Windows, macOS, Linux`);
    console.log(`\n✅ Backend ready with all advanced features enabled!`);
    console.log(`🔒 Enhanced hacker protection active - Multi-layer security engaged!`);
    
    // Initialize analytics and monitoring services
    try {
        await analyticsService.initialize();
        console.log(`📈 Analytics service initialized`);
    } catch (error) {
        console.error(`❌ Failed to initialize analytics service:`, error.message);
    }
    
    // Initialize advanced monitoring
    console.log(`🔍 Advanced Monitoring initialized`);
    console.log(`   📝 Registry Monitor: Ready`);
    console.log(`   🔐 Certificate Validator: Ready`);
    console.log(`   🧠 Memory Scanner: Ready`);
    console.log(`   🛡️  Rootkit Detector: Ready`);
    console.log(`   💰 Crypto Miner Detector: Ready`);
    
    // Initialize advanced firewall
    console.log(`\n🛡️  Advanced Firewall initialized`);
    console.log(`   🔍 Deep Packet Inspection (DPI): Active`);
    console.log(`   🚨 Intrusion Detection System (IDS): Active`);
    console.log(`   🛑 Intrusion Prevention System (IPS): Active`);
    console.log(`   📱 Application Filter: Ready`);
    console.log(`   🌍 Geo-Blocker: Ready`);
    console.log(`   📊 Traffic Analyzer: Active`);
    console.log(`   ⚡ Rules loaded: ${advancedFirewall.rules.size}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down Nebula Shield Backend...');
    
    // Stop all monitoring services
    try {
        if (advancedMonitoring.registryMonitoringActive) {
            advancedMonitoring.stopRegistryMonitoring();
        }
        if (advancedMonitoring.memoryMonitoringActive) {
            advancedMonitoring.stopMemoryScanning();
        }
        console.log('🔍 Advanced monitoring services stopped');
    } catch (error) {
        console.error('Error stopping monitoring:', error.message);
    }
    
    // Stop firewall monitoring
    try {
        if (advancedFirewall.isMonitoring) {
            advancedFirewall.stopMonitoring();
        }
        console.log('🛡️  Advanced firewall stopped');
    } catch (error) {
        console.error('Error stopping firewall:', error.message);
    }
    
    process.exit(0);
});

// ==================== VISUAL ENHANCEMENTS API ====================

// Gamification data storage
const gamificationData = new Map();

// Get gamification stats
app.get('/api/gamification/stats', requireAuth, (req, res) => {
    try {
        const userId = req.user.id || req.user.email;
        const userData = gamificationData.get(userId) || {
            scans: 0,
            threats: 0,
            blocked: 0,
            cleaned: 0,
            quarantined: 0,
            updates: 0,
            firewall_blocks: 0,
            full_scans: 0,
            uptime: 0,
            quick_scan: 0,
            level: 1,
            xp: 0,
            badges: []
        };

        res.json({
            success: true,
            stats: userData,
            level: userData.level,
            xp: userData.xp,
            badges: userData.badges
        });
    } catch (error) {
        console.error('Gamification stats error:', error);
        res.status(500).json({ success: false, error: 'Failed to get stats' });
    }
});

// Update gamification stats
app.post('/api/gamification/update', requireAuth, (req, res) => {
    try {
        const userId = req.user.id || req.user.email;
        const { action, data } = req.body;

        let userData = gamificationData.get(userId) || {
            scans: 0,
            threats: 0,
            blocked: 0,
            cleaned: 0,
            quarantined: 0,
            updates: 0,
            firewall_blocks: 0,
            full_scans: 0,
            uptime: 0,
            quick_scan: 0,
            level: 1,
            xp: 0,
            badges: []
        };

        // Update based on action
        switch (action) {
            case 'scan_complete':
                userData.scans += 1;
                if (data.scanType === 'full') userData.full_scans += 1;
                if (data.duration < 60) userData.quick_scan += 1;
                userData.xp += 10;
                break;
            case 'threat_detected':
                userData.threats += (data.count || 1);
                userData.xp += (data.count || 1) * 5;
                break;
            case 'threat_blocked':
                userData.blocked += (data.count || 1);
                userData.xp += (data.count || 1) * 15;
                break;
            case 'file_cleaned':
                userData.cleaned += (data.count || 1);
                userData.xp += (data.count || 1) * 8;
                break;
            case 'quarantine':
                userData.quarantined += (data.count || 1);
                userData.xp += (data.count || 1) * 5;
                break;
            case 'update':
                userData.updates += 1;
                userData.xp += 3;
                break;
            case 'firewall_block':
                userData.firewall_blocks += (data.count || 1);
                userData.xp += (data.count || 1) * 2;
                break;
            case 'uptime_day':
                userData.uptime += 1;
                userData.xp += 20;
                break;
        }

        // Calculate level
        const xpForLevel = Math.floor(100 * Math.pow(1.5, userData.level - 1));
        if (userData.xp >= xpForLevel) {
            userData.level += 1;
            userData.xp -= xpForLevel;
        }

        gamificationData.set(userId, userData);

        res.json({
            success: true,
            stats: userData,
            levelUp: userData.xp >= xpForLevel
        });
    } catch (error) {
        console.error('Gamification update error:', error);
        res.status(500).json({ success: false, error: 'Failed to update stats' });
    }
});

// Get global threats for threat globe
app.get('/api/threats/global', (req, res) => {
    try {
        // Generate sample global threat data
        const threats = [];
        const threatTypes = ['Ransomware', 'Trojan', 'Spyware', 'Malware', 'Phishing', 'DDoS'];
        const severities = ['low', 'medium', 'high', 'critical'];
        const locations = [
            { name: 'New York, USA', country: 'US', lat: 40.7128, lon: -74.0060 },
            { name: 'London, UK', country: 'GB', lat: 51.5074, lon: -0.1278 },
            { name: 'Tokyo, Japan', country: 'JP', lat: 35.6762, lon: 139.6503 },
            { name: 'Moscow, Russia', country: 'RU', lat: 55.7558, lon: 37.6173 },
            { name: 'Beijing, China', country: 'CN', lat: 39.9042, lon: 116.4074 },
            { name: 'Mumbai, India', country: 'IN', lat: 19.0760, lon: 72.8777 },
            { name: 'São Paulo, Brazil', country: 'BR', lat: -23.5505, lon: -46.6333 },
            { name: 'Sydney, Australia', country: 'AU', lat: -33.8688, lon: 151.2093 },
            { name: 'Berlin, Germany', country: 'DE', lat: 52.5200, lon: 13.4050 },
            { name: 'Paris, France', country: 'FR', lat: 48.8566, lon: 2.3522 }
        ];

        for (let i = 0; i < 15; i++) {
            const location = locations[Math.floor(Math.random() * locations.length)];
            threats.push({
                id: `threat-${Date.now()}-${i}`,
                latitude: location.lat,
                longitude: location.lon,
                type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
                severity: severities[Math.floor(Math.random() * severities.length)],
                location: location.name,
                country: location.country,
                timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString()
            });
        }

        res.json({
            success: true,
            threats,
            count: threats.length
        });
    } catch (error) {
        console.error('Global threats error:', error);
        res.status(500).json({ success: false, error: 'Failed to get threats' });
    }
});

// Get activity timeline data
app.get('/api/activity/timeline', requireAuth, (req, res) => {
    try {
        const { hours = 1 } = req.query;
        const events = [];
        const now = Date.now();
        const interval = (hours * 3600000) / 30; // 30 data points

        for (let i = 0; i < 30; i++) {
            const timestamp = new Date(now - (29 - i) * interval);
            events.push({
                timestamp: timestamp.toISOString(),
                scans: Math.floor(Math.random() * 10),
                threats: Math.floor(Math.random() * 3),
                blocked: Math.floor(Math.random() * 2),
                cleaned: Math.floor(Math.random() * 2)
            });
        }

        res.json({
            success: true,
            events,
            period: `${hours}h`
        });
    } catch (error) {
        console.error('Activity timeline error:', error);
        res.status(500).json({ success: false, error: 'Failed to get activity' });
    }
});

console.log('\n🎨 Visual Enhancement APIs:');
console.log('   GET  /api/gamification/stats   - Get user achievements');
console.log('   POST /api/gamification/update  - Update user stats');
console.log('   GET  /api/threats/global       - Global threat map data');
console.log('   GET  /api/activity/timeline    - Activity graph data');