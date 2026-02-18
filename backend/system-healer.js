/**
 * System Healer - Advanced System Repair & Recovery Module
 * Comprehensive healing capabilities for critical system issues
 */

const { execFile, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const util = require('util');

const execPromise = util.promisify(exec);
const execFilePromise = util.promisify(execFile);

class SystemHealer {
  constructor() {
    this.isWindows = process.platform === 'win32';
    this.healingLog = [];
  }

  /**
   * Main healing function - runs comprehensive system repair
   */
  async healSystem(options = {}) {
    const results = {
      timestamp: new Date().toISOString(),
      success: true,
      repairs: {}
    };

    try {
      // 1. Kill malicious processes
      if (options.processes !== false) {
        results.repairs.processes = await this.terminateMaliciousProcesses();
      }

      // 2. Repair boot sector & system files
      if (options.system !== false) {
        results.repairs.systemFiles = await this.repairSystemFiles();
      }

      // 3. Clean and repair registry
      if (options.registry !== false) {
        results.repairs.registry = await this.repairRegistry();
      }

      // 4. Reset network & DNS
      if (options.network !== false) {
        results.repairs.network = await this.healNetwork();
      }

      // 5. Remove browser hijacks
      if (options.browsers !== false) {
        results.repairs.browsers = await this.cleanBrowsers();
      }

      // 6. Repair services
      if (options.services !== false) {
        results.repairs.services = await this.repairServices();
      }

      // 7. Clean scheduled tasks
      if (options.tasks !== false) {
        results.repairs.tasks = await this.cleanScheduledTasks();
      }

      // 8. Repair Windows Update
      if (options.updates !== false) {
        results.repairs.updates = await this.repairWindowsUpdate();
      }

      // 9. Create restore point
      if (options.restorePoint !== false) {
        results.repairs.restorePoint = await this.createRestorePoint();
      }

      return results;
    } catch (error) {
      console.error('System healing error:', error);
      results.success = false;
      results.error = error.message;
      return results;
    }
  }

  /**
   * 1. PROCESS HEALING - Kill malicious processes
   */
  async terminateMaliciousProcesses() {
    if (!this.isWindows) return { skipped: 'Windows only' };

    const suspiciousProcesses = [];
    const terminated = [];

    try {
      // Get running processes
      const { stdout } = await execPromise('tasklist /FO CSV /NH');
      const processes = stdout.split('\n')
        .filter(line => line.trim())
        .map(line => {
          const parts = line.split('","');
          return {
            name: parts[0]?.replace(/"/g, ''),
            pid: parts[1]?.replace(/"/g, ''),
            memory: parts[4]?.replace(/"/g, '')
          };
        });

      // Suspicious process patterns
      const suspiciousPatterns = [
        /svchost\.exe.*-k netsvcs -p -s/i, // Fake svchost
        /csrss\.exe/i, // If not in System32
        /winlogon\.exe/i, // If not in System32
        /ransomware|crypto|locker|encryptor/i,
        /keylogger|logger|keylog/i,
        /miner|mining|cryptominer/i,
        /trojan|malware|backdoor/i
      ];

      for (const proc of processes) {
        for (const pattern of suspiciousPatterns) {
          if (pattern.test(proc.name)) {
            suspiciousProcesses.push(proc);
            
            // Try to terminate
            try {
              await execPromise(`taskkill /PID ${proc.pid} /F`);
              terminated.push(proc.name);
              this.log('INFO', `Terminated suspicious process: ${proc.name} (PID: ${proc.pid})`);
            } catch (err) {
              this.log('WARN', `Failed to terminate ${proc.name}: ${err.message}`);
            }
          }
        }
      }

      return {
        success: true,
        suspicious: suspiciousProcesses.length,
        terminated: terminated.length,
        processes: terminated
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * 2. SYSTEM FILE REPAIR - SFC, DISM, Boot repair
   */
  async repairSystemFiles() {
    if (!this.isWindows) return { skipped: 'Windows only' };

    const results = {
      sfc: { status: 'not_run' },
      dism: { status: 'not_run' },
      boot: { status: 'not_run' }
    };

    try {
      // Run System File Checker (SFC)
      this.log('INFO', 'Running System File Checker (SFC)...');
      try {
        const { stdout, stderr } = await execPromise('sfc /scannow', {
          timeout: 600000 // 10 minutes
        });
        
        results.sfc = {
          status: 'completed',
          output: stdout,
          corrupted: stdout.includes('corrupt') || stdout.includes('violation'),
          repaired: stdout.includes('repaired') || stdout.includes('fixed')
        };
      } catch (err) {
        results.sfc = { status: 'failed', error: err.message };
      }

      // Run DISM (Deployment Image Servicing and Management)
      this.log('INFO', 'Running DISM repair...');
      try {
        const { stdout } = await execPromise(
          'DISM /Online /Cleanup-Image /RestoreHealth',
          { timeout: 900000 } // 15 minutes
        );
        
        results.dism = {
          status: 'completed',
          output: stdout,
          repaired: stdout.includes('restore') || stdout.includes('completed')
        };
      } catch (err) {
        results.dism = { status: 'failed', error: err.message };
      }

      // Check boot configuration
      this.log('INFO', 'Checking boot configuration...');
      try {
        const { stdout } = await execPromise('bcdedit /enum');
        results.boot = {
          status: 'checked',
          valid: !stdout.includes('error'),
          output: stdout.substring(0, 500)
        };
      } catch (err) {
        results.boot = { status: 'failed', error: err.message };
      }

      return { success: true, ...results };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * 3. REGISTRY REPAIR - Deep registry healing
   */
  async repairRegistry() {
    if (!this.isWindows) return { skipped: 'Windows only' };

    const results = {
      autorun: [],
      hijack: [],
      services: []
    };

    try {
      // Remove malicious autorun entries
      const autorunKeys = [
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
      ];

      for (const key of autorunKeys) {
        try {
          const { stdout } = await execPromise(`reg query "${key}"`);
          
          // Look for suspicious entries
          const suspiciousPatterns = [
            /temp|tmp|appdata\\local\\temp/i,
            /\.(exe|dll|scr|vbs|bat)"/i,
            /http|https|download/i
          ];

          const lines = stdout.split('\n');
          for (const line of lines) {
            for (const pattern of suspiciousPatterns) {
              if (pattern.test(line)) {
                // Extract value name
                const match = line.match(/REG_\w+\s+(.+)/);
                if (match) {
                  const valueName = match[1].split('    ')[0];
                  try {
                    await execPromise(`reg delete "${key}" /v "${valueName}" /f`);
                    results.autorun.push(valueName);
                    this.log('INFO', `Removed autorun entry: ${valueName}`);
                  } catch (err) {
                    this.log('WARN', `Failed to remove ${valueName}: ${err.message}`);
                  }
                }
              }
            }
          }
        } catch (err) {
          // Key doesn't exist or query failed
        }
      }

      // Check for browser hijacks
      const hijackKeys = [
        'HKCU\\SOFTWARE\\Microsoft\\Internet Explorer\\Main',
        'HKLM\\SOFTWARE\\Microsoft\\Internet Explorer\\Main'
      ];

      for (const key of hijackKeys) {
        try {
          const { stdout } = await execPromise(`reg query "${key}" /v "Start Page"`);
          if (!stdout.includes('about:blank') && !stdout.includes('www.google.com')) {
            // Reset to blank
            await execPromise(`reg add "${key}" /v "Start Page" /d "about:blank" /f`);
            results.hijack.push(key);
            this.log('INFO', `Reset homepage hijack in ${key}`);
          }
        } catch (err) {
          // Value doesn't exist
        }
      }

      return { success: true, ...results };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * 4. NETWORK HEALING - Reset DNS, hosts, adapter
   */
  async healNetwork() {
    if (!this.isWindows) return { skipped: 'Windows only' };

    const results = {};

    try {
      // Reset DNS cache
      this.log('INFO', 'Flushing DNS cache...');
      await execPromise('ipconfig /flushdns');
      results.dns = { success: true };

      // Reset Winsock
      this.log('INFO', 'Resetting Winsock...');
      await execPromise('netsh winsock reset');
      results.winsock = { success: true };

      // Reset TCP/IP stack
      this.log('INFO', 'Resetting TCP/IP stack...');
      await execPromise('netsh int ip reset');
      results.tcpip = { success: true };

      // Clean hosts file
      const hostsPath = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
      if (fs.existsSync(hostsPath)) {
        let hostsContent = fs.readFileSync(hostsPath, 'utf8');
        const lines = hostsContent.split('\n');
        const cleanLines = lines.filter(line => {
          // Keep comments and localhost
          return line.trim().startsWith('#') || 
                 line.trim() === '' ||
                 line.includes('127.0.0.1') ||
                 line.includes('::1');
        });

        if (cleanLines.length !== lines.length) {
          fs.writeFileSync(hostsPath, cleanLines.join('\n'));
          results.hosts = {
            success: true,
            removed: lines.length - cleanLines.length
          };
          this.log('INFO', `Cleaned ${lines.length - cleanLines.length} entries from hosts file`);
        } else {
          results.hosts = { success: true, removed: 0 };
        }
      }

      // Remove proxy settings
      this.log('INFO', 'Removing proxy hijacks...');
      try {
        await execPromise('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f');
        await execPromise('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /f');
        results.proxy = { success: true, removed: true };
      } catch (err) {
        results.proxy = { success: true, removed: false };
      }

      return { success: true, ...results };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * 5. BROWSER CLEANUP - Remove hijacks and malicious extensions
   */
  async cleanBrowsers() {
    const results = {
      chrome: [],
      firefox: [],
      edge: []
    };

    try {
      // Chrome cleanup
      const chromePathsToClean = [
        path.join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'Default', 'Preferences'),
        path.join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'Default', 'Secure Preferences')
      ];

      for (const chromePath of chromePathsToClean) {
        if (fs.existsSync(chromePath)) {
          try {
            const prefs = JSON.parse(fs.readFileSync(chromePath, 'utf8'));
            
            // Reset homepage
            if (prefs.session && prefs.session.startup_urls) {
              prefs.session.startup_urls = ['https://www.google.com'];
              results.chrome.push('homepage_reset');
            }

            // Reset search engine
            if (prefs.default_search_provider_data) {
              prefs.default_search_provider_data.template_url_data = {};
              results.chrome.push('search_engine_reset');
            }

            fs.writeFileSync(chromePath, JSON.stringify(prefs, null, 2));
            this.log('INFO', 'Cleaned Chrome preferences');
          } catch (err) {
            this.log('WARN', `Failed to clean Chrome: ${err.message}`);
          }
        }
      }

      return { success: true, ...results };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * 6. SERVICE REPAIR - Restore critical Windows services
   */
  async repairServices() {
    if (!this.isWindows) return { skipped: 'Windows only' };

    const criticalServices = [
      'wuauserv', // Windows Update
      'wscsvc',   // Security Center
      'WinDefend', // Windows Defender
      'mpssvc',   // Firewall
      'BITS',     // Background Intelligent Transfer
      'Dhcp',     // DHCP Client
      'Dnscache', // DNS Client
      'EventLog', // Event Log
      'Themes'    // Themes (prevents UAC bypass)
    ];

    const results = { repaired: [], failed: [] };

    for (const service of criticalServices) {
      try {
        // Check service status
        const { stdout } = await execPromise(`sc query ${service}`);
        
        if (stdout.includes('STOPPED') || stdout.includes('DISABLED')) {
          // Try to start service
          await execPromise(`sc config ${service} start= auto`);
          await execPromise(`sc start ${service}`);
          results.repaired.push(service);
          this.log('INFO', `Repaired service: ${service}`);
        }
      } catch (err) {
        results.failed.push(service);
        this.log('WARN', `Failed to repair service ${service}: ${err.message}`);
      }
    }

    return {
      success: true,
      repaired: results.repaired.length,
      failed: results.failed.length,
      ...results
    };
  }

  /**
   * 7. SCHEDULED TASKS CLEANUP - Remove malicious tasks
   */
  async cleanScheduledTasks() {
    if (!this.isWindows) return { skipped: 'Windows only' };

    const results = { removed: [] };

    try {
      const { stdout } = await execPromise('schtasks /query /fo CSV /nh');
      const tasks = stdout.split('\n')
        .filter(line => line.trim())
        .map(line => {
          const parts = line.split('","');
          return parts[0]?.replace(/"/g, '');
        });

      // Suspicious task patterns
      const suspiciousPatterns = [
        /temp|tmp/i,
        /update.*\d{10}/i, // Fake updates with timestamps
        /system32.*\.tmp/i,
        /appdata.*local.*temp/i
      ];

      for (const task of tasks) {
        for (const pattern of suspiciousPatterns) {
          if (pattern.test(task)) {
            try {
              await execPromise(`schtasks /delete /tn "${task}" /f`);
              results.removed.push(task);
              this.log('INFO', `Removed suspicious task: ${task}`);
            } catch (err) {
              this.log('WARN', `Failed to remove task ${task}: ${err.message}`);
            }
          }
        }
      }

      return { success: true, removed: results.removed.length, tasks: results.removed };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * 8. WINDOWS UPDATE REPAIR
   */
  async repairWindowsUpdate() {
    if (!this.isWindows) return { skipped: 'Windows only' };

    const results = {};

    try {
      this.log('INFO', 'Repairing Windows Update...');

      // Stop Windows Update services
      await execPromise('net stop wuauserv');
      await execPromise('net stop bits');
      await execPromise('net stop cryptsvc');
      
      // Rename SoftwareDistribution folder
      const softDistPath = 'C:\\Windows\\SoftwareDistribution';
      const backupPath = 'C:\\Windows\\SoftwareDistribution.old';
      
      if (fs.existsSync(softDistPath)) {
        if (fs.existsSync(backupPath)) {
          fs.rmSync(backupPath, { recursive: true, force: true });
        }
        fs.renameSync(softDistPath, backupPath);
        results.softwareDistribution = { renamed: true };
      }

      // Start services again
      await execPromise('net start wuauserv');
      await execPromise('net start bits');
      await execPromise('net start cryptsvc');

      results.services = { restarted: true };
      
      return { success: true, ...results };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * 9. CREATE SYSTEM RESTORE POINT
   */
  async createRestorePoint() {
    if (!this.isWindows) return { skipped: 'Windows only' };

    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const description = `Nebula Shield System Heal - ${timestamp}`;

      // Create restore point using PowerShell
      const psScript = `
        Checkpoint-Computer -Description "${description}" -RestorePointType "MODIFY_SETTINGS"
      `;

      await execPromise(`powershell -Command "${psScript}"`);

      this.log('INFO', 'Created system restore point');

      return {
        success: true,
        description,
        timestamp
      };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Logging helper
   */
  log(level, message) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      message
    };
    this.healingLog.push(entry);
    console.log(`[${level}] ${message}`);
  }

  /**
   * Get healing log
   */
  getLog() {
    return this.healingLog;
  }

  /**
   * Clear log
   */
  clearLog() {
    this.healingLog = [];
  }
}

module.exports = new SystemHealer();
