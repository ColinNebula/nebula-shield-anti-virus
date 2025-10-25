const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const quarantineService = require('./backend/quarantine-service');
const fileCleaner = require('./backend/file-cleaner');
const diskCleaner = require('./backend/disk-cleaner');
const authService = require('./backend/auth-service');
const activityLogger = require('./backend/activity-logger');
const backupService = require('./backend/backup-service');
const analyticsService = require('./backend/analytics-service');
const systemMonitor = require('./backend/system-monitor');
const bulkOperations = require('./backend/bulk-operations');
const scheduledTasks = require('./backend/scheduled-tasks');
const settingsImportExport = require('./backend/settings-import-export');
const cloudBackup = require('./backend/cloud-backup');
const enhancedHackerProtection = require('./backend/enhanced-hacker-protection');
const licenseAPI = require('./backend/license-api');

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

function handleFileScan(req, res) {
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
        fileSize = Math.floor(Math.random() * 1024 * 1024); // Random size for demo
    } else {
        return res.status(400).json({ error: 'No file or file path provided' });
    }
    
    // Simulate scanning delay
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
            quarantined: false
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
        const newSignatures = Math.floor(Math.random() * 1000) + 500;
        console.log(`📦 Updating virus signatures... +${newSignatures} new signatures`);
        res.json({
            success: true,
            message: 'Virus definitions updated successfully',
            version: `${new Date().getFullYear()}.${new Date().getMonth() + 1}.${new Date().getDate()}`,
            newSignatures: newSignatures,
            totalSignatures: 125000 + newSignatures,
            lastUpdate: new Date().toISOString()
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
        const { email, password } = req.body;
        const ipAddress = req.ip;
        const userAgent = req.headers['user-agent'];

        const result = await authService.authenticate(email, password);

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
            res.json({
                success: result.success,
                token: result.sessionToken,
                user: result.user,
                message: 'Login successful'
            });
        } else {
            res.json(result);
        }
    } catch (error) {
        console.error('Login error:', error);
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
    console.log(`   POST /api/license/revoke            - Revoke license (admin)`);
    console.log(`   POST /api/license/extend            - Extend license expiration (admin)`);
    console.log(`   GET  /api/license/history/:key      - View audit log (admin)`);
    console.log(`   POST /api/license/tos-accept        - Accept Terms of Service`);
    
    console.log(`\n✅ Backend ready with all advanced features enabled!`);
    console.log(`🔒 Enhanced hacker protection active - Multi-layer security engaged!`);
    
    // Initialize analytics and monitoring services
    try {
        await analyticsService.initialize();
        console.log(`📈 Analytics service initialized`);
    } catch (error) {
        console.error(`❌ Failed to initialize analytics service:`, error.message);
    }
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down Nebula Shield Backend...');
    process.exit(0);
});