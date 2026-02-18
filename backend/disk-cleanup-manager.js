/**
 * Disk Cleanup Manager
 * Identifies and removes temporary files, cache, and junk data
 */

const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const fg = require('fast-glob');
const os = require('os');

class DiskCleanupManager {
    constructor() {
        this.isWindows = os.platform() === 'win32';
        this.cleanupCategories = {
            tempFiles: {
                name: 'Temporary Files',
                description: 'System and user temporary files',
                paths: [],
                size: 0,
                files: [],
                minAgeDays: 0
            },
            browserCache: {
                name: 'Browser Cache',
                description: 'Chrome, Edge, Firefox cache files',
                paths: [],
                size: 0,
                files: [],
                minAgeDays: 0
            },
            windowsUpdate: {
                name: 'Windows Update Cache',
                description: 'Downloaded Windows updates',
                paths: [],
                size: 0,
                files: [],
                minAgeDays: 7
            },
            recycleBin: {
                name: 'Recycle Bin',
                description: 'Deleted files in Recycle Bin',
                paths: [],
                size: 0,
                files: [],
                minAgeDays: 0
            },
            downloads: {
                name: 'Old Downloads',
                description: 'Files in Downloads older than 30 days',
                paths: [],
                size: 0,
                files: [],
                minAgeDays: 30
            }
        };

        this.lastScanResults = null;
    }

    getCategoryRoots(categoryName) {
        const userProfile = process.env.USERPROFILE || os.homedir();
        const winDir = process.env.WINDIR || 'C:\\Windows';

        const roots = {
            tempFiles: [
                process.env.TEMP,
                process.env.TMP,
                path.join(process.env.LOCALAPPDATA || '', 'Temp'),
                path.join(winDir, 'Temp')
            ],
            browserCache: [
                path.join(userProfile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data'),
                path.join(userProfile, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data'),
                path.join(userProfile, 'AppData', 'Local', 'Mozilla', 'Firefox', 'Profiles')
            ],
            windowsUpdate: [
                path.join(winDir, 'SoftwareDistribution', 'Download')
            ],
            recycleBin: [
                'C:\\$Recycle.Bin'
            ],
            downloads: [
                path.join(userProfile, 'Downloads')
            ]
        };

        return (roots[categoryName] || []).filter(Boolean);
    }

    isPathWithinRoots(filePath, roots) {
        const resolvedFile = path.resolve(filePath);
        return roots.some(root => {
            const resolvedRoot = path.resolve(root);
            if (this.isWindows) {
                return resolvedFile.toLowerCase().startsWith(resolvedRoot.toLowerCase() + path.sep);
            }
            return resolvedFile.startsWith(resolvedRoot + path.sep);
        });
    }

    /**
     * Analyze disk for cleanable files
     */
    async analyzeDisk() {
        console.log('🔍 Starting disk cleanup analysis...');
        
        // Reset categories
        for (const key in this.cleanupCategories) {
            this.cleanupCategories[key].files = [];
            this.cleanupCategories[key].size = 0;
        }

        await Promise.all([
            this.scanTempFiles(),
            this.scanBrowserCache(),
            this.scanWindowsUpdateCache(),
            this.scanRecycleBin(),
            this.scanOldDownloads()
        ]);

        this.lastScanResults = {
            timestamp: new Date().toISOString(),
            categories: this.cleanupCategories,
            totalSize: Object.values(this.cleanupCategories).reduce((sum, cat) => sum + cat.size, 0),
            totalFiles: Object.values(this.cleanupCategories).reduce((sum, cat) => sum + cat.files.length, 0)
        };

        console.log(`✅ Disk analysis complete: ${this.formatBytes(this.lastScanResults.totalSize)} can be freed`);
        
        return this.lastScanResults;
    }

    /**
     * Scan temporary files
     */
    async scanTempFiles() {
        const tempPaths = [
            process.env.TEMP,
            process.env.TMP,
            path.join(process.env.LOCALAPPDATA, 'Temp'),
            'C:\\Windows\\Temp'
        ].filter(p => p && fsSync.existsSync(p));

        for (const tempPath of tempPaths) {
            try {
                const files = await fg([path.join(tempPath, '**/*')], {
                    onlyFiles: true,
                    dot: true,
                    suppressErrors: true,
                    ignore: ['**/*.lock', '**/node_modules/**'],
                    deep: 3, // Limit directory depth for faster scanning
                });

                // Limit to 200 files for performance
                for (const file of files.slice(0, 200)) {
                    try {
                        const stats = await fs.stat(file);
                        this.cleanupCategories.tempFiles.files.push({
                            path: file,
                            size: stats.size,
                            modified: stats.mtime
                        });
                        this.cleanupCategories.tempFiles.size += stats.size;
                    } catch (error) {
                        // Skip inaccessible files
                    }
                }
            } catch (error) {
                console.error(`Error scanning temp path ${tempPath}:`, error.message);
            }
        }
    }

    /**
     * Scan browser cache
     */
    async scanBrowserCache() {
        const userProfile = process.env.USERPROFILE;
        const cachePaths = [
            // Chrome
            path.join(userProfile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Cache'),
            // Edge
            path.join(userProfile, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'),
            // Firefox
            path.join(userProfile, 'AppData', 'Local', 'Mozilla', 'Firefox', 'Profiles'),
        ].filter(p => fsSync.existsSync(p));

        for (const cachePath of cachePaths) {
            try {
                const files = await fg([path.join(cachePath, '**/*')], {
                    onlyFiles: true,
                    suppressErrors: true,
                    ignore: ['**/Cookies', '**/History', '**/Bookmarks'],
                    deep: 3,
                });

                for (const file of files.slice(0, 150)) {
                    try {
                        const stats = await fs.stat(file);
                        this.cleanupCategories.browserCache.files.push({
                            path: file,
                            size: stats.size,
                            modified: stats.mtime
                        });
                        this.cleanupCategories.browserCache.size += stats.size;
                    } catch (error) {
                        // Skip
                    }
                }
            } catch (error) {
                // Skip
            }
        }
    }

    /**
     * Scan Windows Update cache
     */
    async scanWindowsUpdateCache() {
        const updatePath = 'C:\\Windows\\SoftwareDistribution\\Download';
        
        if (!fsSync.existsSync(updatePath)) {
            return;
        }

        try {
            const files = await fg([path.join(updatePath, '**/*')], {
                onlyFiles: true,
                suppressErrors: true,
                deep: 2,
            });

            for (const file of files.slice(0, 100)) {
                try {
                    const stats = await fs.stat(file);
                    this.cleanupCategories.windowsUpdate.files.push({
                        path: file,
                        size: stats.size,
                        modified: stats.mtime
                    });
                    this.cleanupCategories.windowsUpdate.size += stats.size;
                } catch (error) {
                    // Skip
                }
            }
        } catch (error) {
            // May not have permissions
        }
    }

    /**
     * Scan Recycle Bin
     */
    async scanRecycleBin() {
        const recycleBinPath = 'C:\\$Recycle.Bin';
        
        if (!fsSync.existsSync(recycleBinPath)) {
            return;
        }

        try {
            const files = await fg([path.join(recycleBinPath, '**/*')], {
                onlyFiles: true,
                suppressErrors: true
            });

            for (const file of files.slice(0, 100)) {
                try {
                    const stats = await fs.stat(file);
                    this.cleanupCategories.recycleBin.files.push({
                        path: file,
                        size: stats.size,
                        modified: stats.mtime
                    });
                    this.cleanupCategories.recycleBin.size += stats.size;
                } catch (error) {
                    // Skip
                }
            }
        } catch (error) {
            // May not have permissions
        }
    }

    /**
     * Scan old downloads
     */
    async scanOldDownloads() {
        const downloadsPath = path.join(process.env.USERPROFILE, 'Downloads');
        
        if (!fsSync.existsSync(downloadsPath)) {
            return;
        }

        try {
            const files = await fg([path.join(downloadsPath, '*')], {
                onlyFiles: true,
                suppressErrors: true
            });

            const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);

            for (const file of files) {
                try {
                    const stats = await fs.stat(file);
                    if (stats.mtime.getTime() < thirtyDaysAgo) {
                        this.cleanupCategories.downloads.files.push({
                            path: file,
                            size: stats.size,
                            modified: stats.mtime
                        });
                        this.cleanupCategories.downloads.size += stats.size;
                    }
                } catch (error) {
                    // Skip
                }
            }
        } catch (error) {
            // Skip
        }
    }

    /**
     * Clean a specific category
     */
    async cleanCategory(categoryName) {
        if (!this.cleanupCategories[categoryName]) {
            const validCategories = Object.keys(this.cleanupCategories).join(', ');
            return {
                success: false,
                error: `Invalid category: "${categoryName}". Valid categories: ${validCategories}`
            };
        }

        const category = this.cleanupCategories[categoryName];
        const allowedRoots = this.getCategoryRoots(categoryName);
        const minAgeMs = (category.minAgeDays || 0) * 24 * 60 * 60 * 1000;
        
        // Check if we have scanned data
        if (!category.files || category.files.length === 0) {
            return {
                success: true,
                cleaned: 0,
                filesDeleted: 0,
                deletedCount: 0,
                deletedSize: 0,
                location: category.name,
                message: `${category.name} is already clean.`
            };
        }

        let deletedCount = 0;
        let deletedSize = 0;
        let skippedCount = 0;
        const errors = [];
        const now = Date.now();

        console.log(`🧹 Cleaning ${category.name}...`);

        for (const file of category.files) {
            try {
                if (allowedRoots.length > 0 && !this.isPathWithinRoots(file.path, allowedRoots)) {
                    skippedCount++;
                    errors.push({
                        file: file.path,
                        error: 'Skipped: path outside allowed cleanup roots'
                    });
                    continue;
                }

                if (minAgeMs > 0) {
                    try {
                        const stats = await fs.stat(file.path);
                        if (now - stats.mtime.getTime() < minAgeMs) {
                            skippedCount++;
                            continue;
                        }
                    } catch (error) {
                        skippedCount++;
                        errors.push({ file: file.path, error: error.message });
                        continue;
                    }
                }

                await fs.unlink(file.path);
                deletedCount++;
                deletedSize += file.size;
            } catch (error) {
                if (error.code === 'ENOENT') {
                    skippedCount++;
                    continue;
                }
                errors.push({
                    file: file.path,
                    error: error.message
                });
            }
        }

        // Update category
        category.files = [];
        category.size = 0;

        console.log(`✅ Cleaned ${deletedCount} files, freed ${this.formatBytes(deletedSize)}`);

        return {
            success: true,
            cleaned: deletedSize,
            filesDeleted: deletedCount,
            deletedCount,
            deletedSize,
            skippedCount,
            location: category.name,
            message: deletedCount === 0
                ? `${category.name} is already clean.`
                : `Cleaned ${deletedCount} files from ${category.name}`,
            errors: errors.length > 0 ? errors : undefined
        };
    }

    /**
     * Clean all categories
     */
    async cleanAll() {
        const results = {};
        let totalDeleted = 0;
        let totalSize = 0;

        for (const categoryName in this.cleanupCategories) {
            const result = await this.cleanCategory(categoryName);
            results[categoryName] = result;
            if (result.success) {
                totalDeleted += result.deletedCount;
                totalSize += result.deletedSize;
            }
        }

        return {
            success: true,
            totalDeleted,
            totalSize,
            totalCleaned: totalSize,
            totalFiles: totalDeleted,
            categories: results,
            message: totalSize === 0
                ? 'No files to clean (all areas already clean)'
                : `Freed ${this.formatBytes(totalSize)} by deleting ${totalDeleted} files`
        };
    }

    /**
     * Get cleanup results
     */
    getCleanupResults() {
        if (!this.lastScanResults) {
            return {
                success: false,
                error: 'No scan results available. Run analyzeDisk() first.'
            };
        }

        return {
            success: true,
            results: this.lastScanResults,
            summary: {
                totalFiles: this.lastScanResults.totalFiles,
                totalSize: this.lastScanResults.totalSize,
                totalSizeFormatted: this.formatBytes(this.lastScanResults.totalSize),
                categories: Object.keys(this.cleanupCategories).map(key => ({
                    id: key,
                    name: this.cleanupCategories[key].name,
                    description: this.cleanupCategories[key].description,
                    fileCount: this.cleanupCategories[key].files.length,
                    size: this.cleanupCategories[key].size,
                    sizeFormatted: this.formatBytes(this.cleanupCategories[key].size)
                }))
            }
        };
    }

    /**
     * Format bytes to human readable
     */
    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    }
}

// Export singleton instance
module.exports = new DiskCleanupManager();
