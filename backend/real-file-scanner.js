/**
 * Real File Scanner Module
 * Scans actual files on disk instead of generating mock data
 */

const fg = require('fast-glob');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

// Optional VirusTotal integration
let virusTotalService = null;
try {
    virusTotalService = require('./virustotal-service');
} catch (error) {
    console.log('VirusTotal service not available');
}

class RealFileScanner {
    constructor() {
        this.currentScan = null;
        this.scanHistory = [];
        this.useVirusTotal = false; // Set to true to enable VT scanning
        // Common malware file patterns and signatures
        this.suspiciousPatterns = [
            /\.(exe|dll|scr|bat|cmd|vbs|js|ps1)$/i,
            /trojan|virus|malware|keylog|backdoor|rat|inject|hack/i,
            /\.(tmp|temp).*\.(exe|dll)$/i,
        ];
        // Known dangerous file hashes (example - in production use virus database)
        this.knownMalwareHashes = new Set([
            // Add known malware file hashes here
            // Example: 'd41d8cd98f00b204e9800998ecf8427e'
        ]);
    }

    /**
     * Start a real file system scan
     */
    async startScan(scanType = 'quick', scanPath = 'C:\\') {
        if (this.currentScan && this.currentScan.status === 'running') {
            throw new Error('A scan is already in progress');
        }

        const scanId = Date.now().toString();
        this.currentScan = {
            id: scanId,
            type: scanType,
            path: scanPath,
            status: 'running',
            startTime: new Date(),
            totalFiles: 0,
            scannedFiles: 0,
            threatsFound: 0,
            results: [],
            currentFile: null,
        };

        // Run scan asynchronously
        this.runScan(scanType, scanPath, scanId).catch(error => {
            console.error('Scan error:', error);
            if (this.currentScan && this.currentScan.id === scanId) {
                this.currentScan.status = 'error';
                this.currentScan.error = error.message;
            }
        });

        return {
            success: true,
            scanId,
            message: `${scanType} scan started`,
        };
    }

    /**
     * Run the actual file scan
     */
    async runScan(scanType, scanPath, scanId) {
        try {
            // Define scan patterns based on scan type
            let patterns;
            let maxFiles;
            
            if (scanType === 'quick') {
                // Quick scan: Common Windows system folders and user temp
                // NOTE: fast-glob requires forward slashes, even on Windows
                patterns = [
                    path.join(process.env.TEMP, '**/*').replace(/\\/g, '/'),
                    path.join(process.env.LOCALAPPDATA, 'Temp', '**/*').replace(/\\/g, '/'),
                    'C:/Windows/Temp/**/*',
                    path.join(process.env.USERPROFILE, 'Downloads', '**/*').replace(/\\/g, '/'),
                    path.join(process.env.USERPROFILE, 'AppData', 'Local', 'Temp', '**/*').replace(/\\/g, '/'),
                ];
                maxFiles = 1000;  // Limit quick scan to 1000 files
            } else if (scanType === 'full') {
                // Full scan: Entire drive (with sensible exclusions)
                // NOTE: fast-glob requires forward slashes, even on Windows
                patterns = [
                    (scanPath + '**/*').replace(/\\/g, '/'),
                ];
                maxFiles = 10000; // Limit full scan to 10000 files for performance
            } else {
                // Custom scan
                patterns = [(scanPath + '**/*').replace(/\\/g, '/')];
                maxFiles = 5000;
            }

            // Scan options
            const scanOptions = {
                dot: false, // Don't include hidden files by default
                onlyFiles: true,
                suppressErrors: true,
                ignore: [
                    '**/node_modules/**',
                    '**/.git/**',
                    '**/System Volume Information/**',
                    '**/$RECYCLE.BIN/**',
                    '**/Windows/WinSxS/**', // Large folder, mostly safe
                ],
            };

            console.log(`Starting ${scanType} scan on: ${scanPath}`);
            
            // Get all files to scan
            const files = await fg(patterns, scanOptions);
            
            // Limit files for performance
            const filesToScan = files.slice(0, maxFiles);
            this.currentScan.totalFiles = filesToScan.length;
            
            console.log(`Found ${filesToScan.length} files to scan`);

            // Scan each file
            for (let i = 0; i < filesToScan.length; i++) {
                if (this.currentScan.status !== 'running') {
                    break; // Scan was cancelled
                }

                const filePath = filesToScan[i];
                this.currentScan.currentFile = filePath;
                this.currentScan.scannedFiles = i + 1;

                try {
                    const scanResult = await this.scanFile(filePath);
                    
                    if (scanResult.threat_type !== 'CLEAN') {
                        this.currentScan.threatsFound++;
                        this.currentScan.results.push(scanResult);
                    }
                } catch (error) {
                    // Skip files we can't access
                    continue;
                }

                // Update progress every 10 files
                if (i % 10 === 0) {
                    console.log(`Scan progress: ${i}/${filesToScan.length}`);
                }
            }

            // Scan complete
            this.currentScan.status = 'completed';
            this.currentScan.endTime = new Date();
            this.currentScan.duration = Math.round(
                (this.currentScan.endTime - this.currentScan.startTime) / 1000
            );

            // Add to history
            this.scanHistory.unshift({
                ...this.currentScan,
                id: scanId,
            });

            // Keep only last 10 scans
            if (this.scanHistory.length > 10) {
                this.scanHistory = this.scanHistory.slice(0, 10);
            }

            console.log(`Scan completed: ${this.currentScan.scannedFiles} files scanned, ${this.currentScan.threatsFound} threats found`);
            
        } catch (error) {
            console.error('Scan error:', error);
            this.currentScan.status = 'error';
            this.currentScan.error = error.message;
        }
    }

    /**
     * Scan an individual file for threats
     */
    async scanFile(filePath) {
        try {
            const stats = await fs.stat(filePath);
            const fileName = path.basename(filePath);
            
            // Check file extension and name for suspicious patterns
            let isSuspicious = false;
            let suspicionReason = '';
            
            // Check suspicious patterns
            for (const pattern of this.suspiciousPatterns) {
                if (pattern.test(filePath) || pattern.test(fileName)) {
                    isSuspicious = true;
                    suspicionReason = 'Suspicious file pattern';
                    break;
                }
            }

            // Calculate file hash for known malware check (only for suspicious files or executable)
            let fileHash = null;
            if (isSuspicious || /\.(exe|dll|scr)$/i.test(fileName)) {
                try {
                    const fileBuffer = await fs.readFile(filePath);
                    // Only hash first 1MB to avoid performance issues
                    const dataToHash = fileBuffer.slice(0, 1024 * 1024);
                    fileHash = crypto.createHash('md5').update(dataToHash).digest('hex');
                    
                    // Check against known malware hashes
                    if (this.knownMalwareHashes.has(fileHash)) {
                        isSuspicious = true;
                        suspicionReason = 'Known malware signature';
                    }

                    // Optional: Check with VirusTotal for suspicious files
                    if (this.useVirusTotal && virusTotalService && isSuspicious) {
                        const sha256Hash = crypto.createHash('sha256').update(dataToHash).digest('hex');
                        const vtResult = await virusTotalService.scanFileHash(sha256Hash);
                        
                        if (vtResult.success && vtResult.isMalicious) {
                            isSuspicious = true;
                            suspicionReason = `VirusTotal detection: ${vtResult.threatName}`;
                        }
                    }
                } catch (error) {
                    // Can't read file, skip hashing
                }
            }

            // Determine threat level
            let threatType = 'CLEAN';
            let threatName = '';
            
            if (isSuspicious) {
                threatType = 'SUSPICIOUS';
                threatName = `Suspicious.${suspicionReason.replace(/\s+/g, '.')}`;
                
                // Additional checks for high-risk files
                if (/trojan|virus|malware|keylog/i.test(fileName)) {
                    threatType = 'MALWARE';
                    threatName = `PUA.${fileName.substring(0, 20)}`;
                } else if (fileHash && this.knownMalwareHashes.has(fileHash)) {
                    threatType = 'MALWARE';
                    threatName = `Trojan.Generic.${fileHash.substring(0, 8)}`;
                }
            }

            return {
                file_path: filePath,
                threat_type: threatType,
                threat_name: threatName,
                file_size: stats.size,
                file_hash: fileHash,
                scan_time: new Date().toISOString(),
            };
        } catch (error) {
            // File access error, mark as clean but inaccessible
            return {
                file_path: filePath,
                threat_type: 'CLEAN',
                threat_name: '',
                file_size: 0,
                scan_time: new Date().toISOString(),
                error: error.message,
            };
        }
    }

    /**
     * Get current scan status
     */
    getScanStatus() {
        if (!this.currentScan) {
            return {
                success: false,
                message: 'No scan in progress',
            };
        }

        const progress = this.currentScan.totalFiles > 0
            ? Math.round((this.currentScan.scannedFiles / this.currentScan.totalFiles) * 100)
            : 0;

        return {
            success: true,
            scan: {
                id: this.currentScan.id,
                type: this.currentScan.type,
                status: this.currentScan.status,
                progress,
                totalFiles: this.currentScan.totalFiles,
                scannedFiles: this.currentScan.scannedFiles,
                threatsFound: this.currentScan.threatsFound,
                currentFile: this.currentScan.currentFile,
                startTime: this.currentScan.startTime,
            },
        };
    }

    /**
     * Get scan results
     */
    getScanResults() {
        if (!this.currentScan) {
            return {
                success: false,
                message: 'No scan results available',
            };
        }

        return {
            success: true,
            scan: {
                id: this.currentScan.id,
                type: this.currentScan.type,
                path: this.currentScan.path,
                status: this.currentScan.status,
                totalFiles: this.currentScan.totalFiles,
                scannedFiles: this.currentScan.scannedFiles,
                threatsFound: this.currentScan.threatsFound,
                results: this.currentScan.results,
                duration: this.currentScan.duration,
                startTime: this.currentScan.startTime,
                endTime: this.currentScan.endTime,
            },
        };
    }

    /**
     * Get scan history
     */
    getScanHistory() {
        return {
            success: true,
            history: this.scanHistory.map(scan => ({
                id: scan.id,
                type: scan.type,
                path: scan.path,
                status: scan.status,
                totalFiles: scan.scannedFiles,
                threatsFound: scan.threatsFound,
                duration: scan.duration,
                timestamp: scan.startTime,
            })),
        };
    }

    /**
     * Cancel current scan
     */
    cancelScan() {
        if (this.currentScan && this.currentScan.status === 'running') {
            this.currentScan.status = 'cancelled';
            return { success: true, message: 'Scan cancelled' };
        }
        return { success: false, message: 'No scan to cancel' };
    }
}

// Export singleton instance
module.exports = new RealFileScanner();
