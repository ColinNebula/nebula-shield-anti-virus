/**
 * Disk Cleanup & Optimization Service
 * Cleans unnecessary files and frees up disk space
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

class DiskCleaner {
  constructor() {
    this.isWindows = os.platform() === 'win32';
    this.isMac = os.platform() === 'darwin';
    this.isLinux = os.platform() === 'linux';
    
    // Common temporary directories
    this.tempDirs = this.getTempDirectories();
  }

  getTempDirectories() {
    const dirs = {
      windows: [
        path.join(os.homedir(), 'AppData', 'Local', 'Temp'),
        path.join(process.env.WINDIR || 'C:\\Windows', 'Temp'),
        path.join(os.homedir(), 'AppData', 'Local', 'Microsoft', 'Windows', 'INetCache'),
        path.join(os.homedir(), 'AppData', 'Local', 'CrashDumps'),
      ],
      mac: [
        '/tmp',
        path.join(os.homedir(), 'Library', 'Caches'),
        path.join(os.homedir(), '.Trash'),
      ],
      linux: [
        '/tmp',
        '/var/tmp',
        path.join(os.homedir(), '.cache'),
        path.join(os.homedir(), '.local', 'share', 'Trash'),
      ]
    };

    if (this.isWindows) return dirs.windows;
    if (this.isMac) return dirs.mac;
    if (this.isLinux) return dirs.linux;
    return [];
  }

  /**
   * Analyze disk space usage
   */
  async analyzeDiskSpace() {
    try {
      const analysis = {
        recycleBin: await this.analyzeRecycleBin(),
        tempFiles: await this.analyzeTempFiles(),
        downloads: await this.analyzeDownloads(),
        browserCache: await this.analyzeBrowserCache(),
        logs: await this.analyzeSystemLogs(),
        oldFiles: await this.analyzeOldFiles(),
      };

      const totalCleanable = Object.values(analysis).reduce((sum, item) => sum + item.size, 0);

      return {
        success: true,
        analysis,
        totalCleanable,
        totalFiles: Object.values(analysis).reduce((sum, item) => sum + item.count, 0),
        recommendations: this.generateRecommendations(analysis),
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Analyze Recycle Bin
   */
  async analyzeRecycleBin() {
    try {
      let size = 0;
      let count = 0;

      if (this.isWindows) {
        // Windows Recycle Bin locations
        const drives = ['C', 'D', 'E', 'F'];
        for (const drive of drives) {
          const recyclePath = `${drive}:\\$Recycle.Bin`;
          if (fs.existsSync(recyclePath)) {
            const result = this.getDirectorySize(recyclePath);
            size += result.size;
            count += result.count;
          }
        }
      } else if (this.isMac) {
        const trashPath = path.join(os.homedir(), '.Trash');
        if (fs.existsSync(trashPath)) {
          const result = this.getDirectorySize(trashPath);
          size = result.size;
          count = result.count;
        }
      } else if (this.isLinux) {
        const trashPath = path.join(os.homedir(), '.local', 'share', 'Trash');
        if (fs.existsSync(trashPath)) {
          const result = this.getDirectorySize(trashPath);
          size = result.size;
          count = result.count;
        }
      }

      return { size, count, location: 'Recycle Bin' };
    } catch (error) {
      return { size: 0, count: 0, location: 'Recycle Bin', error: error.message };
    }
  }

  /**
   * Analyze temporary files
   */
  async analyzeTempFiles() {
    let totalSize = 0;
    let totalCount = 0;

    for (const tempDir of this.tempDirs) {
      if (fs.existsSync(tempDir)) {
        try {
          const result = this.getDirectorySize(tempDir);
          totalSize += result.size;
          totalCount += result.count;
        } catch (error) {
          // Skip inaccessible directories
        }
      }
    }

    return { size: totalSize, count: totalCount, location: 'Temporary Files' };
  }

  /**
   * Analyze Downloads folder
   */
  async analyzeDownloads() {
    const downloadsPath = path.join(os.homedir(), 'Downloads');
    
    if (!fs.existsSync(downloadsPath)) {
      return { size: 0, count: 0, location: 'Downloads' };
    }

    try {
      const files = fs.readdirSync(downloadsPath);
      const now = Date.now();
      const thirtyDaysAgo = now - (30 * 24 * 60 * 60 * 1000);
      
      let size = 0;
      let count = 0;

      files.forEach(file => {
        try {
          const filePath = path.join(downloadsPath, file);
          const stats = fs.statSync(filePath);
          
          // Count files older than 30 days
          if (stats.mtimeMs < thirtyDaysAgo) {
            size += stats.size;
            count++;
          }
        } catch (error) {
          // Skip inaccessible files
        }
      });

      return { size, count, location: 'Downloads (30+ days old)' };
    } catch (error) {
      return { size: 0, count: 0, location: 'Downloads', error: error.message };
    }
  }

  /**
   * Analyze browser cache
   */
  async analyzeBrowserCache() {
    let totalSize = 0;
    let totalCount = 0;

    const cachePaths = [];

    if (this.isWindows) {
      cachePaths.push(
        path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Cache'),
        path.join(os.homedir(), 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'),
        path.join(os.homedir(), 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
      );
    } else if (this.isMac) {
      cachePaths.push(
        path.join(os.homedir(), 'Library', 'Caches', 'Google', 'Chrome'),
        path.join(os.homedir(), 'Library', 'Caches', 'Firefox')
      );
    }

    for (const cachePath of cachePaths) {
      if (fs.existsSync(cachePath)) {
        try {
          const result = this.getDirectorySize(cachePath);
          totalSize += result.size;
          totalCount += result.count;
        } catch (error) {
          // Skip inaccessible directories
        }
      }
    }

    return { size: totalSize, count: totalCount, location: 'Browser Cache' };
  }

  /**
   * Analyze system logs
   */
  async analyzeSystemLogs() {
    let totalSize = 0;
    let totalCount = 0;

    const logPaths = [];

    if (this.isWindows) {
      logPaths.push(
        path.join(process.env.WINDIR || 'C:\\Windows', 'Logs'),
        path.join(process.env.WINDIR || 'C:\\Windows', 'Temp')
      );
    } else if (this.isLinux || this.isMac) {
      logPaths.push('/var/log');
    }

    for (const logPath of logPaths) {
      if (fs.existsSync(logPath)) {
        try {
          const files = fs.readdirSync(logPath);
          files.forEach(file => {
            if (file.endsWith('.log') || file.endsWith('.old')) {
              try {
                const filePath = path.join(logPath, file);
                const stats = fs.statSync(filePath);
                totalSize += stats.size;
                totalCount++;
              } catch (error) {
                // Skip inaccessible files
              }
            }
          });
        } catch (error) {
          // Skip inaccessible directories
        }
      }
    }

    return { size: totalSize, count: totalCount, location: 'System Logs' };
  }

  /**
   * Analyze old/large files
   */
  async analyzeOldFiles() {
    // This would scan common directories for files older than 180 days
    // For now, return placeholder
    return { size: 0, count: 0, location: 'Old Files (180+ days)' };
  }

  /**
   * Get directory size recursively
   */
  getDirectorySize(dirPath, maxDepth = 3, currentDepth = 0) {
    let totalSize = 0;
    let totalCount = 0;

    if (currentDepth > maxDepth) {
      return { size: totalSize, count: totalCount };
    }

    try {
      const files = fs.readdirSync(dirPath);

      files.forEach(file => {
        try {
          const filePath = path.join(dirPath, file);
          const stats = fs.statSync(filePath);

          if (stats.isDirectory()) {
            const subResult = this.getDirectorySize(filePath, maxDepth, currentDepth + 1);
            totalSize += subResult.size;
            totalCount += subResult.count;
          } else {
            totalSize += stats.size;
            totalCount++;
          }
        } catch (error) {
          // Skip inaccessible files
        }
      });
    } catch (error) {
      // Skip inaccessible directories
    }

    return { size: totalSize, count: totalCount };
  }

  /**
   * Clean Recycle Bin
   */
  async cleanRecycleBin() {
    try {
      let cleaned = 0;
      let count = 0;

      if (this.isWindows) {
        // Empty Recycle Bin using PowerShell
        try {
          execSync('powershell.exe -Command "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"', { 
            stdio: 'ignore',
            timeout: 30000 
          });
          const analysis = await this.analyzeRecycleBin();
          cleaned = analysis.size;
          count = analysis.count;
        } catch (error) {
          // Fallback: manually delete files
          const drives = ['C', 'D', 'E'];
          for (const drive of drives) {
            const recyclePath = `${drive}:\\$Recycle.Bin`;
            if (fs.existsSync(recyclePath)) {
              const result = this.deleteDirectoryContents(recyclePath);
              cleaned += result.size;
              count += result.count;
            }
          }
        }
      } else if (this.isMac) {
        const trashPath = path.join(os.homedir(), '.Trash');
        if (fs.existsSync(trashPath)) {
          const result = this.deleteDirectoryContents(trashPath);
          cleaned = result.size;
          count = result.count;
        }
      } else if (this.isLinux) {
        const trashPath = path.join(os.homedir(), '.local', 'share', 'Trash', 'files');
        if (fs.existsSync(trashPath)) {
          const result = this.deleteDirectoryContents(trashPath);
          cleaned = result.size;
          count = result.count;
        }
      }

      return {
        success: true,
        cleaned,
        filesDeleted: count,
        location: 'Recycle Bin'
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        location: 'Recycle Bin'
      };
    }
  }

  /**
   * Clean temporary files
   */
  async cleanTempFiles() {
    let totalCleaned = 0;
    let totalCount = 0;

    for (const tempDir of this.tempDirs) {
      if (fs.existsSync(tempDir)) {
        try {
          const result = this.deleteDirectoryContents(tempDir);
          totalCleaned += result.size;
          totalCount += result.count;
        } catch (error) {
          // Skip inaccessible directories
        }
      }
    }

    return {
      success: true,
      cleaned: totalCleaned,
      filesDeleted: totalCount,
      location: 'Temporary Files'
    };
  }

  /**
   * Clean old downloads
   */
  async cleanOldDownloads(daysOld = 30) {
    const downloadsPath = path.join(os.homedir(), 'Downloads');
    
    if (!fs.existsSync(downloadsPath)) {
      return { success: true, cleaned: 0, filesDeleted: 0, location: 'Downloads' };
    }

    try {
      const files = fs.readdirSync(downloadsPath);
      const now = Date.now();
      const cutoffDate = now - (daysOld * 24 * 60 * 60 * 1000);
      
      let cleaned = 0;
      let count = 0;

      files.forEach(file => {
        try {
          const filePath = path.join(downloadsPath, file);
          const stats = fs.statSync(filePath);
          
          if (stats.mtimeMs < cutoffDate) {
            cleaned += stats.size;
            fs.unlinkSync(filePath);
            count++;
          }
        } catch (error) {
          // Skip files that can't be deleted
        }
      });

      return {
        success: true,
        cleaned,
        filesDeleted: count,
        location: `Downloads (${daysOld}+ days old)`
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        location: 'Downloads'
      };
    }
  }

  /**
   * Delete directory contents
   */
  deleteDirectoryContents(dirPath, maxDepth = 2, currentDepth = 0) {
    let totalSize = 0;
    let totalCount = 0;

    if (currentDepth > maxDepth) {
      return { size: totalSize, count: totalCount };
    }

    try {
      const files = fs.readdirSync(dirPath);

      files.forEach(file => {
        try {
          const filePath = path.join(dirPath, file);
          const stats = fs.statSync(filePath);

          if (stats.isDirectory()) {
            const subResult = this.deleteDirectoryContents(filePath, maxDepth, currentDepth + 1);
            totalSize += subResult.size;
            totalCount += subResult.count;
            
            try {
              fs.rmdirSync(filePath);
            } catch (error) {
              // Directory might not be empty or inaccessible
            }
          } else {
            totalSize += stats.size;
            fs.unlinkSync(filePath);
            totalCount++;
          }
        } catch (error) {
          // Skip files that can't be deleted
        }
      });
    } catch (error) {
      // Skip inaccessible directories
    }

    return { size: totalSize, count: totalCount };
  }

  /**
   * Generate recommendations
   */
  generateRecommendations(analysis) {
    const recommendations = [];

    if (analysis.recycleBin.size > 100 * 1024 * 1024) {
      recommendations.push({
        priority: 'high',
        action: 'Empty Recycle Bin',
        savings: analysis.recycleBin.size,
        description: `Free up ${this.formatBytes(analysis.recycleBin.size)} by emptying the Recycle Bin`
      });
    }

    if (analysis.tempFiles.size > 500 * 1024 * 1024) {
      recommendations.push({
        priority: 'high',
        action: 'Clean Temporary Files',
        savings: analysis.tempFiles.size,
        description: `Remove ${this.formatBytes(analysis.tempFiles.size)} of temporary files`
      });
    }

    if (analysis.downloads.size > 1024 * 1024 * 1024) {
      recommendations.push({
        priority: 'medium',
        action: 'Clean Old Downloads',
        savings: analysis.downloads.size,
        description: `Delete ${analysis.downloads.count} old downloads (${this.formatBytes(analysis.downloads.size)})`
      });
    }

    if (analysis.browserCache.size > 200 * 1024 * 1024) {
      recommendations.push({
        priority: 'low',
        action: 'Clear Browser Cache',
        savings: analysis.browserCache.size,
        description: `Clear ${this.formatBytes(analysis.browserCache.size)} of browser cache`
      });
    }

    return recommendations;
  }

  /**
   * Format bytes to human readable
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  }

  /**
   * Clean all (one-click cleanup)
   */
  async cleanAll() {
    const results = {
      recycleBin: await this.cleanRecycleBin(),
      tempFiles: await this.cleanTempFiles(),
      oldDownloads: await this.cleanOldDownloads(30),
    };

    const totalCleaned = Object.values(results).reduce((sum, result) => sum + (result.cleaned || 0), 0);
    const totalFiles = Object.values(results).reduce((sum, result) => sum + (result.filesDeleted || 0), 0);

    return {
      success: true,
      totalCleaned,
      totalFiles,
      results,
      message: `Freed up ${this.formatBytes(totalCleaned)} by deleting ${totalFiles} files`
    };
  }
}

module.exports = new DiskCleaner();
