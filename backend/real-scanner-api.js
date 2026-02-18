const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Load native C++ scanner
let nativeScanner = null;
let scannerAvailable = false;

try {
    nativeScanner = require('./build/Release/scanner.node');
    nativeScanner.initScanner();
    scannerAvailable = true;
    console.log('✅ Native C++ scanner loaded successfully');
} catch (error) {
    console.error('❌ Failed to load native scanner:', error.message);
    console.log('ℹ️  To build scanner: cd backend && npm install && npm run build:scanner');
    console.log('ℹ️  Falling back to JavaScript-based scanning');
}

// Helper function to convert threat type code to name
function getThreatTypeName(typeCode) {
    const types = {
        0: 'CLEAN',
        1: 'VIRUS',
        2: 'MALWARE',
        3: 'TROJAN',
        4: 'SUSPICIOUS'
    };
    return types[typeCode] || 'UNKNOWN';
}

// REAL file scanning endpoint
app.post('/api/scan/file', async (req, res) => {
    try {
        const { file_path } = req.body;
        
        if (!file_path) {
            return res.status(400).json({ error: 'file_path required' });
        }
        
        // Check if file exists
        if (!fs.existsSync(file_path)) {
            return res.status(404).json({ error: 'File not found' });
        }
        
        const fileStats = fs.statSync(file_path);
        
        // Use native C++ scanner if available
        if (scannerAvailable && nativeScanner) {
            try {
                const scanStart = Date.now();
                const result = nativeScanner.scanFile(file_path);
                const scanDuration = Date.now() - scanStart;
                
                return res.json({
                    id: Date.now(),
                    file_path: result.file_path,
                    threat_type: getThreatTypeName(result.threat_type),
                    threat_name: result.threat_name || null,
                    confidence: result.confidence,
                    file_size: fileStats.size,
                    file_hash: result.file_hash,
                    scan_time: new Date().toISOString(),
                    scan_duration_ms: scanDuration,
                    quarantined: false,
                    scanner_engine: 'native_cpp'
                });
            } catch (scanError) {
                console.error('Native scan error:', scanError);
                // Fall through to JavaScript scanning
            }
        }
        
        // Fallback JavaScript-based scanning
        const jsResult = await performJavaScriptScan(file_path, fileStats);
        res.json(jsResult);
        
    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({ error: error.message });
    }
});

// REAL directory scanning endpoint
app.post('/api/scan/directory', async (req, res) => {
    try {
        const { directory_path, recursive = true } = req.body;
        
        if (!directory_path) {
            return res.status(400).json({ error: 'directory_path required' });
        }
        
        if (!fs.existsSync(directory_path)) {
            return res.status(404).json({ error: 'Directory not found' });
        }
        
        // Use native C++ scanner if available
        if (scannerAvailable && nativeScanner) {
            try {
                const scanStart = Date.now();
                const results = nativeScanner.scanDirectory(directory_path, recursive);
                const scanDuration = Date.now() - scanStart;
                
                const formattedResults = results.map((result, index) => ({
                    id: Date.now() + index,
                    file_path: result.file_path,
                    threat_type: getThreatTypeName(result.threat_type),
                    threat_name: result.threat_name || null,
                    confidence: result.confidence,
                    file_hash: result.file_hash,
                    scan_duration_ms: result.scan_duration_ms
                }));
                
                const threatsFound = formattedResults.filter(r => r.threat_type !== 'CLEAN').length;
                
                return res.json({
                    directory_path,
                    total_files: formattedResults.length,
                    threats_found: threatsFound,
                    scan_duration_ms: scanDuration,
                    results: formattedResults,
                    scanner_engine: 'native_cpp'
                });
            } catch (scanError) {
                console.error('Native directory scan error:', scanError);
            }
        }
        
        // Fallback JavaScript-based directory scanning
        const jsResults = await performJavaScriptDirectoryScan(directory_path, recursive);
        res.json(jsResults);
        
    } catch (error) {
        console.error('Directory scan error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Quarantine file
app.post('/api/quarantine/file', async (req, res) => {
    try {
        const { file_path } = req.body;
        
        if (!file_path) {
            return res.status(400).json({ error: 'file_path required' });
        }
        
        if (scannerAvailable && nativeScanner) {
            const result = nativeScanner.quarantineFile(file_path);
            return res.json(result);
        }
        
        // Fallback JavaScript quarantine
        const quarantineDir = path.join(__dirname, '../data/quarantine');
        if (!fs.existsSync(quarantineDir)) {
            fs.mkdirSync(quarantineDir, { recursive: true });
        }
        
        const fileName = path.basename(file_path);
        const timestamp = Date.now();
        const quarantinePath = path.join(quarantineDir, `${timestamp}_${fileName}`);
        
        fs.renameSync(file_path, quarantinePath);
        
        res.json({
            success: true,
            original_path: file_path,
            quarantine_path: quarantinePath,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Clean file
app.post('/api/clean/file', async (req, res) => {
    try {
        const { file_path } = req.body;
        
        if (!file_path) {
            return res.status(400).json({ error: 'file_path required' });
        }
        
        if (scannerAvailable && nativeScanner) {
            const result = nativeScanner.cleanFile(file_path);
            return res.json(result);
        }
        
        res.json({
            success: false,
            repairable: false,
            message: 'File cleaning requires native scanner. Build with: npm run build:scanner'
        });
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get scanner statistics
app.get('/api/scanner/stats', (req, res) => {
    try {
        if (scannerAvailable && nativeScanner) {
            const stats = nativeScanner.getStats();
            return res.json({
                ...stats,
                scanner_available: true,
                scanner_engine: 'native_cpp'
            });
        }
        
        res.json({
            scanner_available: false,
            scanner_engine: 'javascript_fallback',
            message: 'Native scanner not available'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'Nebula Shield Real Scanner API',
        scanner_available: scannerAvailable,
        scanner_engine: scannerAvailable ? 'native_cpp' : 'javascript_fallback',
        timestamp: new Date().toISOString()
    });
});

// JavaScript fallback scanning functions
async function performJavaScriptScan(filePath, fileStats) {
    // Read file and perform basic pattern matching
    const content = fs.readFileSync(filePath, 'utf-8').toLowerCase();
    
    const virusPatterns = [
        /wannacry/i,
        /petya/i,
        /ransomware/i,
        /trojan/i,
        /keylogger/i,
        /backdoor/i,
        /shellcode/i,
        /exploit/i
    ];
    
    let threatDetected = false;
    let threatName = null;
    
    for (const pattern of virusPatterns) {
        if (pattern.test(content)) {
            threatDetected = true;
            threatName = `Suspicious.${pattern.source}`;
            break;
        }
    }
    
    return {
        id: Date.now(),
        file_path: filePath,
        threat_type: threatDetected ? 'SUSPICIOUS' : 'CLEAN',
        threat_name: threatName,
        confidence: threatDetected ? 0.75 : 1.0,
        file_size: fileStats.size,
        file_hash: 'N/A',
        scan_time: new Date().toISOString(),
        scanner_engine: 'javascript_fallback',
        message: 'Using JavaScript fallback scanner. Build native scanner for better detection.'
    };
}

async function performJavaScriptDirectoryScan(dirPath, recursive) {
    const results = [];
    
    function scanDir(dir) {
        const items = fs.readdirSync(dir);
        
        for (const item of items) {
            const fullPath = path.join(dir, item);
            const stats = fs.statSync(fullPath);
            
            if (stats.isFile()) {
                try {
                    const result = performJavaScriptScan(fullPath, stats);
                    results.push(result);
                } catch (error) {
                    // Skip files that can't be read
                }
            } else if (stats.isDirectory() && recursive) {
                scanDir(fullPath);
            }
        }
    }
    
    scanDir(dirPath);
    
    const threatsFound = results.filter(r => r.threat_type !== 'CLEAN').length;
    
    return {
        directory_path: dirPath,
        total_files: results.length,
        threats_found: threatsFound,
        results,
        scanner_engine: 'javascript_fallback'
    };
}

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        scanner_engine: scannerAvailable ? 'native_cpp' : 'javascript_fallback',
        scanner_available: scannerAvailable,
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

// API info endpoint
app.get('/', (req, res) => {
    res.json({
        name: 'Nebula Shield Scanner API',
        version: '1.0.0',
        engine: scannerAvailable ? 'Native C++' : 'JavaScript Fallback',
        endpoints: {
            scan_file: 'POST /api/scan/file',
            scan_directory: 'POST /api/scan/directory',
            health: 'GET /health'
        }
    });
});

const PORT = process.env.SCANNER_PORT || 8081;
const server = app.listen(PORT, () => {
    console.log(`\n🔬 Nebula Shield Real Scanner API`);
    console.log(`📡 Listening on port ${PORT}`);
    console.log(`🔍 Scanner Engine: ${scannerAvailable ? 'Native C++' : 'JavaScript Fallback'}`);
    console.log(`🌐 API Info: http://localhost:${PORT}/`);
    console.log(`❤️  Health Check: http://localhost:${PORT}/health`);
    if (!scannerAvailable) {
        console.log(`\n⚠️  To enable native C++ scanning:`);
        console.log(`   1. cd backend`);
        console.log(`   2. npm install node-addon-api node-gyp`);
        console.log(`   3. npm run build:scanner\n`);
    }
});

server.on('error', (err) => {
    console.error('❌ Scanner API error:', err);
    process.exit(1);
});

process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down scanner API...');
    server.close(() => {
        process.exit(0);
    });
});

module.exports = app;
