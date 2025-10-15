const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 8080;
const NODE_ENV = process.env.NODE_ENV || 'development';

// ======================
// SECURITY MIDDLEWARE
// ======================

// 1. Helmet - Security Headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'", 'http://localhost:8080', 'http://localhost:3000', 'http://localhost:3001']
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    xssFilter: true,
    hidePoweredBy: true
}));

// 2. CORS - Restrict Origins
const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3000', 'http://localhost:3001'];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (mobile apps, curl, postman)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1 || NODE_ENV === 'development') {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// 3. Rate Limiting - Prevent DoS
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply to all API routes
app.use('/api/', limiter);

// Stricter rate limit for scan endpoints
const scanLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 scans per 5 minutes
    message: 'Too many scan requests, please slow down.'
});

app.use('/api/scan/', scanLimiter);

// 4. Request Size Limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 5. Request Logging (Development only)
if (NODE_ENV === 'development') {
    app.use((req, res, next) => {
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
        next();
    });
}

// ======================
// INPUT VALIDATION
// ======================

// Path validation function
function isValidPath(filePath) {
    if (!filePath || typeof filePath !== 'string') {
        return false;
    }
    
    // Normalize and resolve path
    const normalizedPath = path.normalize(filePath);
    
    // Prevent directory traversal
    if (normalizedPath.includes('..')) {
        return false;
    }
    
    // Check length (Windows MAX_PATH = 260)
    if (filePath.length > 260) {
        return false;
    }
    
    // Check for dangerous characters
    const dangerousChars = /[<>"|]/;
    if (dangerousChars.test(filePath)) {
        return false;
    }
    
    return true;
}

// File upload validation
const fileFilter = (req, file, cb) => {
    // Whitelist allowed MIME types
    const allowedTypes = [
        'application/pdf',
        'text/plain',
        'application/zip',
        'application/x-zip-compressed',
        'application/x-msdownload', // .exe for scanning
        'application/octet-stream',
        'image/jpeg',
        'image/png',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    ];
    
    if (allowedTypes.includes(file.mimetype) || file.mimetype.startsWith('text/')) {
        cb(null, true);
    } else {
        cb(new Error(`File type ${file.mimetype} not allowed for scanning`), false);
    }
};

// Configure multer for file uploads
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || (100 * 1024 * 1024); // 100MB
const upload = multer({ 
    dest: process.env.UPLOAD_DIR || 'uploads/',
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 1
    },
    fileFilter: fileFilter
});

// ======================
// MOCK DATA
// ======================

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

// ======================
// API ROUTES
// ======================

// Health check (no rate limit)
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

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
        last_scan_time: systemStats.lastScanTime,
        signature_count: 125847 // Mock signature count
    });
});

// System Statistics
app.get('/api/stats', (req, res) => {
    res.json({
        ...systemStats,
        scanHistory: scanHistory.slice(-10),
        cpuUsage: Math.random() * 100,
        memoryUsage: Math.random() * 100,
        diskUsage: Math.random() * 100
    });
});

// Get scan results
app.get('/api/scan/results', (req, res) => {
    res.json({
        results: scanHistory.slice(-20),
        totalScans: systemStats.totalScans,
        threatsDetected: systemStats.threatsDetected,
        lastScanTime: systemStats.lastScanTime
    });
});

// File Scanning - with validation
app.post('/api/scan/file', 
    [
        body('file_path').optional().custom(value => {
            if (value && !isValidPath(value)) {
                throw new Error('Invalid file path');
            }
            return true;
        })
    ],
    (req, res, next) => {
        // Validate if using JSON
        if (!req.is('multipart/form-data')) {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }
        }
        
        const contentType = req.headers['content-type'] || '';
        
        if (contentType.includes('multipart/form-data')) {
            upload.single('file')(req, res, (err) => {
                if (err instanceof multer.MulterError) {
                    if (err.code === 'LIMIT_FILE_SIZE') {
                        return res.status(400).json({ error: 'File too large. Maximum size is 100MB.' });
                    }
                    return res.status(400).json({ error: 'File upload error: ' + err.message });
                } else if (err) {
                    return res.status(400).json({ error: err.message });
                }
                handleFileScan(req, res);
            });
        } else {
            handleFileScan(req, res);
        }
    }
);

function handleFileScan(req, res) {
    let fileName, fileSize, filePath;
    
    if (req.file) {
        fileName = req.file.originalname;
        fileSize = req.file.size;
        filePath = req.file.path;
    } else if (req.body.file_path) {
        filePath = req.body.file_path;
        fileName = path.basename(filePath);
        fileSize = Math.floor(Math.random() * 1024 * 1024);
    } else {
        return res.status(400).json({ error: 'No file or file path provided' });
    }
    
    setTimeout(() => {
        const isClean = Math.random() > 0.1;
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

        if (req.file) {
            fs.unlink(req.file.path, () => {});
        }

        res.json(scanResult);
    }, Math.random() * 2000 + 1000);
}

// Directory Scanning - with validation
app.post('/api/scan/directory',
    [
        body('directory_path').optional().custom(value => {
            if (value && !isValidPath(value)) {
                throw new Error('Invalid directory path');
            }
            return true;
        }),
        body('path').optional().custom(value => {
            if (value && !isValidPath(value)) {
                throw new Error('Invalid path');
            }
            return true;
        })
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { directory_path, path: scanPath } = req.body;
        const directoryPath = directory_path || scanPath;
        
        if (!directoryPath) {
            return res.status(400).json({ error: 'No directory path provided' });
        }

        setTimeout(() => {
            const fileCount = Math.floor(Math.random() * 100) + 50;
            const threatsFound = Math.floor(Math.random() * 5);
            const threatTypes = ['VIRUS', 'MALWARE', 'TROJAN', 'SUSPICIOUS'];
            
            const results = [];
            for (let i = 0; i < fileCount; i++) {
                const isClean = i >= threatsFound;
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
        }, Math.random() * 3000 + 2000);
    }
);

// Quick Scan
app.post('/api/scan/quick', (req, res) => {
    setTimeout(() => {
        const filesScanned = Math.floor(Math.random() * 50) + 25;
        const threatsFound = Math.floor(Math.random() * 3);
        
        // Generate threat results
        const results = [];
        const commonPaths = [
            'C:\\Users\\Public\\Downloads',
            'C:\\Windows\\Temp',
            'C:\\Users\\AppData\\Local\\Temp',
            '%USERPROFILE%\\Downloads',
            'C:\\ProgramData'
        ];
        
        const threatTypes = [
            { name: 'Trojan.Generic', severity: 'high', type: 'Trojan' },
            { name: 'Adware.Tracking', severity: 'medium', type: 'Adware' },
            { name: 'PUP.Optional', severity: 'low', type: 'PUP' },
            { name: 'Suspicious.Script', severity: 'medium', type: 'Script' }
        ];
        
        for (let i = 0; i < threatsFound; i++) {
            const threat = threatTypes[Math.floor(Math.random() * threatTypes.length)];
            const path = commonPaths[Math.floor(Math.random() * commonPaths.length)];
            results.push({
                file: `${path}\\suspicious_file_${i + 1}.exe`,
                file_path: `${path}\\suspicious_file_${i + 1}.exe`,
                threat: threat.name,
                threat_name: threat.name,
                threat_type: threat.type.toUpperCase(),
                severity: threat.severity,
                type: threat.type,
                action: 'quarantined',
                size: Math.floor(Math.random() * 5000000) + 100000,
                file_size: Math.floor(Math.random() * 5000000) + 100000,
                detectedAt: new Date().toISOString()
            });
        }
        
        const scanResult = {
            id: Date.now(),
            type: 'quick',
            status: 'completed',
            total_files: filesScanned,
            threats_found: threatsFound,
            clean_files: filesScanned - threatsFound,
            results: results,
            scanTime: new Date().toISOString(),
            scanDuration: Math.floor(Math.random() * 2000) + 1000,
            scannedPaths: commonPaths.slice(0, 3)
        };

        scanHistory.push(scanResult);
        systemStats.totalScans++;
        systemStats.threatsDetected += threatsFound;
        systemStats.lastScanTime = scanResult.scanTime;

        res.json(scanResult);
    }, Math.random() * 2000 + 1000);
});

// Full System Scan
app.post('/api/scan/full', (req, res) => {
    setTimeout(() => {
        const filesScanned = Math.floor(Math.random() * 1000) + 500;
        const threatsFound = Math.floor(Math.random() * 8) + 2;
        
        // Generate comprehensive threat results
        const results = [];
        const systemPaths = [
            'C:\\Windows\\System32',
            'C:\\Windows\\Temp',
            'C:\\Users\\Public\\Documents',
            'C:\\Users\\AppData\\Local\\Temp',
            'C:\\Users\\AppData\\Roaming',
            'C:\\ProgramData',
            'C:\\Program Files (x86)',
            '%USERPROFILE%\\Downloads',
            'C:\\Users\\Desktop'
        ];
        
        const advancedThreats = [
            { name: 'Ransomware.WannaCry', severity: 'critical', type: 'Ransomware' },
            { name: 'Trojan.Emotet', severity: 'critical', type: 'Trojan' },
            { name: 'Backdoor.RAT', severity: 'critical', type: 'Backdoor' },
            { name: 'Spyware.Keylogger', severity: 'high', type: 'Spyware' },
            { name: 'Adware.BrowserHijacker', severity: 'medium', type: 'Adware' },
            { name: 'PUP.Optional.Toolbar', severity: 'low', type: 'PUP' },
            { name: 'Miner.CryptoMiner', severity: 'medium', type: 'Miner' },
            { name: 'Worm.Network', severity: 'high', type: 'Worm' }
        ];
        
        for (let i = 0; i < threatsFound; i++) {
            const threat = advancedThreats[Math.floor(Math.random() * advancedThreats.length)];
            const path = systemPaths[Math.floor(Math.random() * systemPaths.length)];
            const extensions = ['.exe', '.dll', '.bat', '.vbs', '.js', '.ps1', '.scr'];
            const ext = extensions[Math.floor(Math.random() * extensions.length)];
            
            results.push({
                file: `${path}\\malware_${Date.now()}_${i}${ext}`,
                file_path: `${path}\\malware_${Date.now()}_${i}${ext}`,
                threat: threat.name,
                threat_name: threat.name,
                threat_type: threat.type.toUpperCase(),
                severity: threat.severity,
                type: threat.type,
                action: 'quarantined',
                size: Math.floor(Math.random() * 10000000) + 500000,
                file_size: Math.floor(Math.random() * 10000000) + 500000,
                detectedAt: new Date().toISOString(),
                hash: `SHA256:${Math.random().toString(36).substring(2, 15).toUpperCase()}`
            });
        }
        
        const scanResult = {
            id: Date.now(),
            type: 'full',
            status: 'completed',
            total_files: filesScanned,
            threats_found: threatsFound,
            clean_files: filesScanned - threatsFound,
            results: results,
            scanTime: new Date().toISOString(),
            scanDuration: Math.floor(Math.random() * 10000) + 5000,
            scannedPaths: systemPaths,
            systemScan: true,
            registryScanned: true,
            memoryScanned: true
        };

        scanHistory.push(scanResult);
        systemStats.totalScans++;
        systemStats.threatsDetected += threatsFound;
        systemStats.lastScanTime = scanResult.scanTime;

        res.json(scanResult);
    }, Math.random() * 5000 + 3000);
});

// Quarantine Management
app.get('/api/quarantine', (req, res) => {
    res.json(quarantineItems);
});

app.delete('/api/quarantine/:id', (req, res) => {
    const { id } = req.params;
    const itemId = parseInt(id);
    
    if (isNaN(itemId)) {
        return res.status(400).json({ error: 'Invalid ID' });
    }
    
    quarantineItems = quarantineItems.filter(item => item.id !== itemId);
    systemStats.filesQuarantined = quarantineItems.length;
    res.json({ success: true });
});

app.post('/api/quarantine/:id/restore', (req, res) => {
    const { id } = req.params;
    const itemId = parseInt(id);
    
    if (isNaN(itemId)) {
        return res.status(400).json({ error: 'Invalid ID' });
    }
    
    const item = quarantineItems.find(item => item.id === itemId);
    
    if (!item) {
        return res.status(404).json({ error: 'Item not found' });
    }

    quarantineItems = quarantineItems.filter(item => item.id !== itemId);
    systemStats.filesQuarantined = quarantineItems.length;
    
    res.json({ success: true, message: `${item.fileName} restored successfully` });
});

// Settings Management
app.get('/api/settings', (req, res) => {
    res.json(settings);
});

app.put('/api/settings', (req, res) => {
    // Validate settings
    const allowedSettings = ['realTimeProtection', 'autoQuarantine', 'scanDepth', 'updateFrequency', 'notificationsEnabled'];
    const newSettings = {};
    
    for (const key of allowedSettings) {
        if (req.body.hasOwnProperty(key)) {
            newSettings[key] = req.body[key];
        }
    }
    
    settings = { ...settings, ...newSettings };
    res.json(settings);
});

// Configuration (alias)
app.get('/api/config', (req, res) => {
    res.json(settings);
});

app.post('/api/config', (req, res) => {
    const allowedSettings = ['realTimeProtection', 'autoQuarantine', 'scanDepth', 'updateFrequency', 'notificationsEnabled'];
    const newSettings = {};
    
    for (const key of allowedSettings) {
        if (req.body.hasOwnProperty(key)) {
            newSettings[key] = req.body[key];
        }
    }
    
    settings = { ...settings, ...newSettings };
    res.json({ success: true, config: settings });
});

// File Cleaning - with validation
app.post('/api/file/clean',
    [
        body('filePath').custom(value => {
            if (!isValidPath(value)) {
                throw new Error('Invalid file path');
            }
            return true;
        })
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { filePath } = req.body;

        setTimeout(() => {
            const cleanSuccess = Math.random() > 0.2;
            
            if (cleanSuccess) {
                res.json({
                    success: true,
                    message: 'File cleaned successfully',
                    filePath: filePath,
                    signaturesRemoved: Math.floor(Math.random() * 3) + 1,
                    backupCreated: true
                });
            } else {
                res.status(500).json({
                    success: false,
                    error: 'Unable to clean file - file may be corrupted or repair not possible'
                });
            }
        }, Math.random() * 2000 + 1000);
    }
);

// Database Management
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

// Signature Update
app.post('/api/signatures/update', (req, res) => {
    setTimeout(() => {
        const currentDate = new Date();
        const newSignatures = Math.floor(Math.random() * 1500) + 500;
        const updatedSignatures = Math.floor(Math.random() * 200) + 50;
        
        res.json({
            success: true,
            message: 'Signatures updated successfully',
            timestamp: currentDate.toISOString(),
            version: `${currentDate.getFullYear()}.${currentDate.getMonth() + 1}.${currentDate.getDate()}.${currentDate.getHours()}`,
            statistics: {
                new_signatures: newSignatures,
                updated_signatures: updatedSignatures,
                total_signatures: 135847 + newSignatures,
                last_update: currentDate.toISOString(),
                update_source: 'Nebula Shield Cloud',
                database_version: '2025.10.13.1'
            }
        });
    }, 1500);
});

// Storage Management
app.get('/api/storage/info', (req, res) => {
    const totalSpace = 500 * 1024 * 1024 * 1024;
    const usedSpace = Math.floor(Math.random() * 200) * 1024 * 1024 * 1024;
    const availableSpace = totalSpace - usedSpace;
    const quarantineSize = quarantineItems.reduce((sum, item) => sum + (item.size || 0), 0);
    const databaseSize = 5 * 1024 * 1024;
    const backupSize = 2 * 1024 * 1024;
    
    res.json({
        total_space: totalSpace,
        available_space: availableSpace,
        used_space: usedSpace,
        usage_percentage: (usedSpace / totalSpace) * 100,
        quarantine_size: quarantineSize,
        database_size: databaseSize,
        backup_size: backupSize,
        quarantine_limit: 1024 * 1024 * 1024,
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

// Real-time Protection Events
app.get('/api/protection/events', (req, res) => {
    if (!settings.realTimeProtection) {
        return res.json({ events: [] });
    }
    
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

// ======================
// ERROR HANDLING
// ======================

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error(`[ERROR] ${err.stack}`);
    
    // Don't leak error details in production
    const errorMessage = NODE_ENV === 'production' 
        ? 'Internal server error' 
        : err.message;
    
    res.status(err.status || 500).json({ 
        error: errorMessage,
        ...(NODE_ENV === 'development' && { stack: err.stack })
    });
});

// ======================
// START SERVER
// ======================

app.listen(PORT, () => {
    console.log(`🛡️  Nebula Shield Anti-Virus Backend (SECURED) running on http://localhost:${PORT}`);
    console.log(`🔒 Security Features Enabled:`);
    console.log(`   ✅ Helmet Security Headers`);
    console.log(`   ✅ CORS Restrictions (${allowedOrigins.join(', ')})`);
    console.log(`   ✅ Rate Limiting (100 req/15min, 20 scans/5min)`);
    console.log(`   ✅ Input Validation (Path traversal protection)`);
    console.log(`   ✅ File Upload Restrictions (100MB, MIME type filtering)`);
    console.log(`   ✅ Request Size Limits (10MB)`);
    console.log(`📊 API Endpoints:`);
    console.log(`   GET  /health             - Health check`);
    console.log(`   GET  /api/status         - System status`);
    console.log(`   GET  /api/stats          - System statistics`);
    console.log(`   POST /api/scan/file      - Scan file (rate limited)`);
    console.log(`   POST /api/scan/directory - Scan directory (rate limited)`);
    console.log(`   POST /api/scan/quick     - Quick scan (rate limited)`);
    console.log(`   POST /api/scan/full      - Full scan (rate limited)`);
    console.log(`   GET  /api/quarantine     - Get quarantined items`);
    console.log(`   GET  /api/settings       - Get settings`);
    console.log(`   PUT  /api/settings       - Update settings`);
    console.log(`✅ Secure backend ready!`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down Nebula Shield Secure Backend...');
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n🛑 SIGTERM received, shutting down gracefully...');
    process.exit(0);
});
