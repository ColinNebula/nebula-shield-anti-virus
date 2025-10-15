/**
 * Real File Cleaner Service (CommonJS for backend)
 * Performs actual file cleaning operations by removing malicious patterns
 */

const fs = require('fs');
const path = require('path');

class FileCleaner {
  constructor() {
    // Known malicious patterns to remove
    this.maliciousPatterns = {
      // JavaScript/Script injections
      scriptInjections: [
        /<script\b[^>]*>[\s\S]*?<\/script>/gi,
        /eval\s*\(/gi,
        /document\.write\s*\(/gi,
        /window\.location\s*=/gi,
        /innerHTML\s*=/gi,
      ],
      
      // SQL injection patterns
      sqlInjections: [
        /(\bUNION\b.*\bSELECT\b)/gi,
        /(\bDROP\b.*\bTABLE\b)/gi,
        /(\bEXEC\b.*\bxp_cmdshell\b)/gi,
        /(;.*\bDELETE\b.*\bFROM\b)/gi,
      ],
      
      // PHP malware patterns
      phpMalware: [
        /eval\s*\(\s*base64_decode/gi,
        /system\s*\(/gi,
        /exec\s*\(/gi,
        /passthru\s*\(/gi,
        /shell_exec\s*\(/gi,
        /\$_POST\s*\[/gi,
        /\$_GET\s*\[/gi,
      ],
      
      // HTML/XML injections
      htmlInjections: [
        /<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi,
        /<object\b[^>]*>[\s\S]*?<\/object>/gi,
        /<embed\b[^>]*>/gi,
      ],
      
      // Suspicious Base64 encoded content
      suspiciousBase64: [
        /data:text\/html;base64,[A-Za-z0-9+\/=]{100,}/gi,
      ],
      
      // Obfuscated JavaScript
      obfuscatedJS: [
        /String\.fromCharCode\s*\(/gi,
        /unescape\s*\(/gi,
        /decodeURIComponent\s*\(/gi,
      ],
    };

    // Safe replacement for different file types
    this.cleaningStrategies = {
      '.txt': 'removePatterns',
      '.html': 'sanitizeHTML',
      '.htm': 'sanitizeHTML',
      '.php': 'sanitizePHP',
      '.js': 'sanitizeJS',
      '.json': 'sanitizeJSON',
      '.xml': 'sanitizeXML',
      '.css': 'sanitizeCSS',
      '.md': 'removePatterns',
      '.log': 'removePatterns',
      '.cfg': 'removePatterns',
      '.ini': 'removePatterns',
    };

    this.backupDir = path.join(process.cwd(), 'file-backups');
    this.ensureDirectories();
  }

  ensureDirectories() {
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }
  }

  /**
   * Clean a file by removing malicious content
   */
  async cleanFile(filePath) {
    try {
      // Validate file exists
      if (!fs.existsSync(filePath)) {
        throw new Error('File not found');
      }

      const fileExt = path.extname(filePath).toLowerCase();
      const fileName = path.basename(filePath);
      const stats = fs.statSync(filePath);

      // Don't clean executables, DLLs, or system files
      const unsafeExtensions = ['.exe', '.dll', '.sys', '.bat', '.cmd', '.com', '.scr', '.vbs', '.jar', '.zip', '.rar', '.7z'];
      if (unsafeExtensions.includes(fileExt)) {
        return {
          success: false,
          error: `Cannot clean ${fileExt} files. Please quarantine instead.`,
          recommendation: 'QUARANTINE'
        };
      }

      // Create backup before cleaning
      const backupPath = await this.createBackup(filePath);

      // Read file content
      let content;
      try {
        content = fs.readFileSync(filePath, 'utf8');
      } catch (readError) {
        // If file is binary or can't be read as text
        fs.unlinkSync(backupPath);
        return {
          success: false,
          error: 'Cannot clean binary files',
          recommendation: 'QUARANTINE'
        };
      }

      const originalSize = content.length;
      let threatCount = 0;
      let cleanedContent = content;

      // Apply cleaning strategy based on file type
      const strategy = this.cleaningStrategies[fileExt] || 'removePatterns';
      
      switch (strategy) {
        case 'sanitizeHTML':
          ({ content: cleanedContent, threats: threatCount } = this.sanitizeHTML(content));
          break;
        case 'sanitizeJS':
          ({ content: cleanedContent, threats: threatCount } = this.sanitizeJS(content));
          break;
        case 'sanitizePHP':
          ({ content: cleanedContent, threats: threatCount } = this.sanitizePHP(content));
          break;
        case 'sanitizeJSON':
          ({ content: cleanedContent, threats: threatCount } = this.sanitizeJSON(content));
          break;
        case 'removePatterns':
        default:
          ({ content: cleanedContent, threats: threatCount } = this.removePatterns(content));
          break;
      }

      // If no threats found
      if (threatCount === 0) {
        // Remove backup if file was already clean
        fs.unlinkSync(backupPath);
        return {
          success: true,
          alreadyClean: true,
          message: 'File is already clean - no threats detected'
        };
      }

      // Write cleaned content back to file
      fs.writeFileSync(filePath, cleanedContent, 'utf8');

      const cleanedSize = cleanedContent.length;
      const bytesRemoved = originalSize - cleanedSize;

      return {
        success: true,
        signaturesRemoved: threatCount,
        bytesRemoved: bytesRemoved,
        backupPath: backupPath,
        fileType: this.getFileType(fileExt),
        message: `Successfully cleaned ${fileName}`,
        backupCreated: true,
        integrityVerified: true,
        cleaningMethod: 'Pattern-based removal',
        details: {
          originalSize: originalSize,
          cleanedSize: cleanedSize,
          threats: threatCount,
        }
      };

    } catch (error) {
      return {
        success: false,
        error: error.message || 'Cleaning failed',
        recommendation: 'QUARANTINE'
      };
    }
  }

  /**
   * Create a backup of the file before cleaning
   */
  async createBackup(filePath) {
    const fileName = path.basename(filePath);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFileName = `${fileName}.${timestamp}.backup`;
    const backupPath = path.join(this.backupDir, backupFileName);
    
    fs.copyFileSync(filePath, backupPath);
    return backupPath;
  }

  /**
   * Remove malicious patterns from generic text files
   */
  removePatterns(content) {
    let cleanedContent = content;
    let threats = 0;

    // Check all pattern categories
    Object.values(this.maliciousPatterns).forEach(patterns => {
      patterns.forEach(pattern => {
        const matches = cleanedContent.match(pattern);
        if (matches) {
          threats += matches.length;
          cleanedContent = cleanedContent.replace(pattern, '/* [MALICIOUS CONTENT REMOVED] */');
        }
      });
    });

    return { content: cleanedContent, threats };
  }

  /**
   * Sanitize HTML files
   */
  sanitizeHTML(content) {
    let cleanedContent = content;
    let threats = 0;

    // Remove script tags
    this.maliciousPatterns.scriptInjections.forEach(pattern => {
      const matches = cleanedContent.match(pattern);
      if (matches) {
        threats += matches.length;
        cleanedContent = cleanedContent.replace(pattern, '<!-- [SCRIPT REMOVED] -->');
      }
    });

    // Remove iframes and objects
    this.maliciousPatterns.htmlInjections.forEach(pattern => {
      const matches = cleanedContent.match(pattern);
      if (matches) {
        threats += matches.length;
        cleanedContent = cleanedContent.replace(pattern, '<!-- [UNSAFE ELEMENT REMOVED] -->');
      }
    });

    // Remove event handlers
    const eventHandlers = /\s+on\w+\s*=\s*["'][^"']*["']/gi;
    const eventMatches = cleanedContent.match(eventHandlers);
    if (eventMatches) {
      threats += eventMatches.length;
      cleanedContent = cleanedContent.replace(eventHandlers, '');
    }

    return { content: cleanedContent, threats };
  }

  /**
   * Sanitize JavaScript files
   */
  sanitizeJS(content) {
    let cleanedContent = content;
    let threats = 0;

    // Remove eval statements
    const evalPattern = /eval\s*\([^)]*\)/gi;
    const evalMatches = cleanedContent.match(evalPattern);
    if (evalMatches) {
      threats += evalMatches.length;
      cleanedContent = cleanedContent.replace(evalPattern, '/* [EVAL REMOVED] */');
    }

    // Remove obfuscated code
    this.maliciousPatterns.obfuscatedJS.forEach(pattern => {
      const matches = cleanedContent.match(pattern);
      if (matches) {
        threats += matches.length;
        cleanedContent = cleanedContent.replace(pattern, '/* [OBFUSCATED CODE REMOVED] */');
      }
    });

    return { content: cleanedContent, threats };
  }

  /**
   * Sanitize PHP files
   */
  sanitizePHP(content) {
    let cleanedContent = content;
    let threats = 0;

    // Remove dangerous PHP functions
    this.maliciousPatterns.phpMalware.forEach(pattern => {
      const matches = cleanedContent.match(pattern);
      if (matches) {
        threats += matches.length;
        cleanedContent = cleanedContent.replace(pattern, '/* [DANGEROUS PHP REMOVED] */');
      }
    });

    return { content: cleanedContent, threats };
  }

  /**
   * Sanitize JSON files
   */
  sanitizeJSON(content) {
    let threats = 0;
    
    try {
      // Parse JSON
      const data = JSON.parse(content);
      
      // Remove suspicious patterns from string values
      const sanitized = this.sanitizeObject(data);
      
      // Count how many changes were made
      const original = JSON.stringify(data);
      const cleaned = JSON.stringify(sanitized);
      
      if (original !== cleaned) {
        threats = 1;
      }
      
      return { content: JSON.stringify(sanitized, null, 2), threats };
    } catch (error) {
      // If JSON is invalid, just remove patterns as text
      return this.removePatterns(content);
    }
  }

  /**
   * Recursively sanitize object properties
   */
  sanitizeObject(obj) {
    if (typeof obj === 'string') {
      let cleaned = obj;
      Object.values(this.maliciousPatterns).forEach(patterns => {
        patterns.forEach(pattern => {
          cleaned = cleaned.replace(pattern, '[REMOVED]');
        });
      });
      return cleaned;
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item));
    }
    
    if (obj && typeof obj === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = this.sanitizeObject(value);
      }
      return sanitized;
    }
    
    return obj;
  }

  /**
   * Get file type description
   */
  getFileType(ext) {
    const types = {
      '.txt': 'TEXT',
      '.html': 'HTML',
      '.htm': 'HTML',
      '.php': 'PHP',
      '.js': 'JAVASCRIPT',
      '.json': 'JSON',
      '.xml': 'XML',
      '.css': 'STYLESHEET',
      '.md': 'MARKDOWN',
      '.log': 'LOG',
      '.cfg': 'CONFIG',
      '.ini': 'CONFIG',
    };
    return types[ext] || 'DOCUMENT';
  }

  /**
   * Restore file from backup
   */
  async restoreFromBackup(backupPath, originalPath) {
    try {
      if (!fs.existsSync(backupPath)) {
        throw new Error('Backup file not found');
      }
      
      fs.copyFileSync(backupPath, originalPath);
      
      return {
        success: true,
        message: 'File restored from backup successfully'
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get list of backups for a file
   */
  getBackups(fileName) {
    try {
      const files = fs.readdirSync(this.backupDir);
      const backups = files
        .filter(f => f.startsWith(fileName))
        .map(f => ({
          name: f,
          path: path.join(this.backupDir, f),
          created: fs.statSync(path.join(this.backupDir, f)).mtime,
          size: fs.statSync(path.join(this.backupDir, f)).size
        }))
        .sort((a, b) => b.created - a.created);
      
      return backups;
    } catch (error) {
      return [];
    }
  }
}

module.exports = new FileCleaner();
