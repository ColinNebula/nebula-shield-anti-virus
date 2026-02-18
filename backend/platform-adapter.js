/**
 * Nebula Shield - Cross-Platform Compatibility Layer
 * Platform-specific implementations for Windows, macOS, and Linux
 */

const os = require('os');
const { exec, spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const { promisify } = require('util');
const execAsync = promisify(exec);

class PlatformAdapter {
  constructor() {
    this.platform = os.platform();
    this.isWindows = this.platform === 'win32';
    this.isMacOS = this.platform === 'darwin';
    this.isLinux = this.platform === 'linux';
  }

  // Get platform-specific paths
  getPaths() {
    if (this.isWindows) {
      return {
        appData: process.env.APPDATA,
        localAppData: process.env.LOCALAPPDATA,
        programFiles: process.env.PROGRAMFILES,
        temp: process.env.TEMP,
        quarantine: path.join(process.env.LOCALAPPDATA, 'NebulaShield', 'Quarantine'),
        logs: path.join(process.env.LOCALAPPDATA, 'NebulaShield', 'Logs'),
        database: path.join(process.env.LOCALAPPDATA, 'NebulaShield', 'Data'),
      };
    } else if (this.isMacOS) {
      const home = os.homedir();
      return {
        appData: path.join(home, 'Library', 'Application Support'),
        localAppData: path.join(home, 'Library', 'Application Support'),
        programFiles: '/Applications',
        temp: '/tmp',
        quarantine: path.join(home, 'Library', 'Application Support', 'NebulaShield', 'Quarantine'),
        logs: path.join(home, 'Library', 'Logs', 'NebulaShield'),
        database: path.join(home, 'Library', 'Application Support', 'NebulaShield', 'Data'),
      };
    } else {
      // Linux
      const home = os.homedir();
      return {
        appData: path.join(home, '.config'),
        localAppData: path.join(home, '.local', 'share'),
        programFiles: '/opt',
        temp: '/tmp',
        quarantine: path.join(home, '.local', 'share', 'nebula-shield', 'quarantine'),
        logs: path.join(home, '.local', 'share', 'nebula-shield', 'logs'),
        database: path.join(home, '.local', 'share', 'nebula-shield', 'data'),
      };
    }
  }

  // Get running processes
  async getProcesses() {
    if (this.isWindows) {
      return this.getProcessesWindows();
    } else if (this.isMacOS) {
      return this.getProcessesMacOS();
    } else {
      return this.getProcessesLinux();
    }
  }

  async getProcessesWindows() {
    try {
      const { stdout } = await execAsync('wmic process get ProcessId,Name,ExecutablePath,CommandLine /format:csv');
      const lines = stdout.split('\n').filter(line => line.trim());
      const processes = [];

      for (let i = 1; i < lines.length; i++) {
        const parts = lines[i].split(',');
        if (parts.length >= 4) {
          processes.push({
            pid: parseInt(parts[3]),
            name: parts[2],
            path: parts[4],
            commandLine: parts[1],
          });
        }
      }

      return processes;
    } catch (error) {
      console.error('Failed to get Windows processes:', error);
      return [];
    }
  }

  async getProcessesMacOS() {
    try {
      const { stdout } = await execAsync('ps -A -o pid,comm');
      const lines = stdout.split('\n').filter(line => line.trim());
      const processes = [];

      for (let i = 1; i < lines.length; i++) {
        const match = lines[i].trim().match(/^(\d+)\s+(.+)$/);
        if (match) {
          processes.push({
            pid: parseInt(match[1]),
            name: path.basename(match[2]),
            path: match[2],
          });
        }
      }

      return processes;
    } catch (error) {
      console.error('Failed to get macOS processes:', error);
      return [];
    }
  }

  async getProcessesLinux() {
    try {
      const { stdout } = await execAsync('ps -eo pid,comm,cmd');
      const lines = stdout.split('\n').filter(line => line.trim());
      const processes = [];

      for (let i = 1; i < lines.length; i++) {
        const match = lines[i].trim().match(/^(\d+)\s+(\S+)\s+(.+)$/);
        if (match) {
          processes.push({
            pid: parseInt(match[1]),
            name: match[2],
            commandLine: match[3],
          });
        }
      }

      return processes;
    } catch (error) {
      console.error('Failed to get Linux processes:', error);
      return [];
    }
  }

  // Kill process
  async killProcess(pid) {
    if (this.isWindows) {
      return execAsync(`taskkill /F /PID ${pid}`);
    } else {
      return execAsync(`kill -9 ${pid}`);
    }
  }

  // Get firewall status
  async getFirewallStatus() {
    if (this.isWindows) {
      return this.getFirewallStatusWindows();
    } else if (this.isMacOS) {
      return this.getFirewallStatusMacOS();
    } else {
      return this.getFirewallStatusLinux();
    }
  }

  async getFirewallStatusWindows() {
    try {
      const { stdout } = await execAsync('netsh advfirewall show allprofiles state');
      const enabled = stdout.includes('State                                 ON');
      return { enabled, platform: 'Windows Defender Firewall' };
    } catch (error) {
      return { enabled: false, error: error.message };
    }
  }

  async getFirewallStatusMacOS() {
    try {
      const { stdout } = await execAsync('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate');
      const enabled = stdout.includes('enabled');
      return { enabled, platform: 'macOS Application Firewall' };
    } catch (error) {
      return { enabled: false, error: error.message };
    }
  }

  async getFirewallStatusLinux() {
    try {
      // Try UFW first
      try {
        const { stdout } = await execAsync('sudo ufw status');
        const enabled = stdout.includes('Status: active');
        return { enabled, platform: 'UFW' };
      } catch (e) {
        // Try iptables
        const { stdout } = await execAsync('sudo iptables -L -n');
        const hasRules = stdout.split('\n').length > 10;
        return { enabled: hasRules, platform: 'iptables' };
      }
    } catch (error) {
      return { enabled: false, error: error.message };
    }
  }

  // Get antivirus status
  async getAntivirusStatus() {
    if (this.isWindows) {
      return this.getAntivirusStatusWindows();
    } else if (this.isMacOS) {
      return this.getAntivirusStatusMacOS();
    } else {
      return this.getAntivirusStatusLinux();
    }
  }

  async getAntivirusStatusWindows() {
    try {
      const { stdout } = await execAsync('powershell -Command "Get-MpComputerStatus | ConvertTo-Json"');
      const status = JSON.parse(stdout || '{}');

      return {
        enabled: Boolean(status.AntivirusEnabled),
        realTimeProtection: Boolean(status.RealTimeProtectionEnabled),
        definitionsUpToDate: typeof status.AntivirusSignatureAge === 'number'
          ? status.AntivirusSignatureAge < 7
          : false,
        lastScan: status.QuickScanEndTime || null,
        platform: 'Windows Defender',
        available: true,
      };
    } catch (error) {
      return {
        enabled: false,
        realTimeProtection: false,
        definitionsUpToDate: false,
        lastScan: null,
        platform: 'None detected',
        available: false,
        message: 'Windows Defender not available',
        error: error.message
      };
    }
  }

  async getAntivirusStatusMacOS() {
    try {
      // Check for XProtect
      const xprotectPath = '/System/Library/CoreServices/XProtect.bundle';
      const exists = await fs.access(xprotectPath).then(() => true).catch(() => false);
      
      return {
        enabled: exists,
        platform: exists ? 'XProtect' : 'None detected',
        realTimeProtection: exists,
        available: exists,
        message: exists ? undefined : 'No antivirus detected',
      };
    } catch (error) {
      return {
        enabled: false,
        realTimeProtection: false,
        platform: 'None detected',
        available: false,
        message: 'Unable to determine antivirus status',
        error: error.message
      };
    }
  }

  async getAntivirusStatusLinux() {
    try {
      // Check for ClamAV
      const { stdout } = await execAsync('clamav-daemon --version').catch(() => ({ stdout: '' }));
      const hasClamAV = stdout.includes('ClamAV');
      
      if (hasClamAV) {
        const { stdout: status } = await execAsync('systemctl is-active clamav-daemon').catch(() => ({ stdout: 'inactive' }));
        return {
          enabled: status.trim() === 'active',
          platform: 'ClamAV',
          realTimeProtection: status.trim() === 'active',
          available: true,
        };
      }
      
      return {
        enabled: false,
        realTimeProtection: false,
        platform: 'None detected',
        available: false,
        message: 'No antivirus detected'
      };
    } catch (error) {
      return {
        enabled: false,
        realTimeProtection: false,
        platform: 'None detected',
        available: false,
        message: 'Unable to determine antivirus status',
        error: error.message
      };
    }
  }

  // Get system updates status
  async getUpdateStatus() {
    if (this.isWindows) {
      return this.getUpdateStatusWindows();
    } else if (this.isMacOS) {
      return this.getUpdateStatusMacOS();
    } else {
      return this.getUpdateStatusLinux();
    }
  }

  async getUpdateStatusWindows() {
    try {
      const { stdout } = await execAsync('powershell -Command "Get-HotFix | Select-Object -Last 1 | ConvertTo-Json"');
      const lastUpdate = JSON.parse(stdout);
      
      return {
        lastUpdate: lastUpdate.InstalledOn,
        platform: 'Windows Update',
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async getUpdateStatusMacOS() {
    try {
      const { stdout } = await execAsync('softwareupdate --history | head -5');
      return {
        recentUpdates: stdout,
        platform: 'Software Update',
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async getUpdateStatusLinux() {
    try {
      // Try apt (Debian/Ubuntu)
      try {
        const { stdout } = await execAsync('apt list --upgradable 2>/dev/null | wc -l');
        const count = parseInt(stdout.trim()) - 1; // Subtract header line
        return {
          availableUpdates: count,
          platform: 'APT',
        };
      } catch (e) {
        // Try yum (RedHat/CentOS)
        const { stdout } = await execAsync('yum check-update | grep -v "^$" | wc -l');
        const count = parseInt(stdout.trim());
        return {
          availableUpdates: count,
          platform: 'YUM',
        };
      }
    } catch (error) {
      return { error: error.message };
    }
  }

  // Get network connections
  async getNetworkConnections() {
    if (this.isWindows) {
      return this.getNetworkConnectionsWindows();
    } else if (this.isMacOS) {
      return this.getNetworkConnectionsMacOS();
    } else {
      return this.getNetworkConnectionsLinux();
    }
  }

  async getNetworkConnectionsWindows() {
    try {
      const { stdout } = await execAsync('netstat -ano');
      const lines = stdout.split('\n').filter(line => line.includes('ESTABLISHED'));
      const connections = [];

      lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 5) {
          const [protocol, localAddr, remoteAddr, state, pid] = parts;
          connections.push({
            protocol,
            localAddress: localAddr,
            remoteAddress: remoteAddr,
            state,
            pid: parseInt(pid),
          });
        }
      });

      return connections;
    } catch (error) {
      console.error('Failed to get Windows network connections:', error);
      return [];
    }
  }

  async getNetworkConnectionsMacOS() {
    try {
      const { stdout } = await execAsync('netstat -an | grep ESTABLISHED');
      const lines = stdout.split('\n').filter(line => line.trim());
      const connections = [];

      lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 4) {
          connections.push({
            protocol: parts[0],
            localAddress: parts[3],
            remoteAddress: parts[4],
            state: 'ESTABLISHED',
          });
        }
      });

      return connections;
    } catch (error) {
      console.error('Failed to get macOS network connections:', error);
      return [];
    }
  }

  async getNetworkConnectionsLinux() {
    try {
      const { stdout } = await execAsync('netstat -antp 2>/dev/null | grep ESTABLISHED');
      const lines = stdout.split('\n').filter(line => line.trim());
      const connections = [];

      lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 6) {
          connections.push({
            protocol: parts[0],
            localAddress: parts[3],
            remoteAddress: parts[4],
            state: parts[5],
            process: parts[6],
          });
        }
      });

      return connections;
    } catch (error) {
      console.error('Failed to get Linux network connections:', error);
      return [];
    }
  }

  // Get disk usage
  async getDiskUsage() {
    if (this.isWindows) {
      return this.getDiskUsageWindows();
    } else {
      return this.getDiskUsageUnix();
    }
  }

  async getDiskUsageWindows() {
    try {
      const { stdout } = await execAsync('wmic logicaldisk get DeviceID,Size,FreeSpace /format:csv');
      const lines = stdout.split('\n').filter(line => line.trim() && !line.startsWith('Node'));
      const disks = [];

      lines.forEach(line => {
        const parts = line.split(',');
        if (parts.length >= 4 && parts[1]) {
          const size = parseInt(parts[3]) || 0;
          const free = parseInt(parts[2]) || 0;
          disks.push({
            device: parts[1],
            total: size,
            free: free,
            used: size - free,
            usagePercent: size > 0 ? ((size - free) / size * 100).toFixed(2) : 0,
          });
        }
      });

      return disks;
    } catch (error) {
      console.error('Failed to get Windows disk usage:', error);
      return [];
    }
  }

  async getDiskUsageUnix() {
    try {
      const { stdout } = await execAsync('df -k');
      const lines = stdout.split('\n').filter(line => line.trim());
      const disks = [];

      for (let i = 1; i < lines.length; i++) {
        const parts = lines[i].trim().split(/\s+/);
        if (parts.length >= 6) {
          disks.push({
            device: parts[0],
            total: parseInt(parts[1]) * 1024,
            used: parseInt(parts[2]) * 1024,
            free: parseInt(parts[3]) * 1024,
            usagePercent: parts[4],
            mountPoint: parts[5],
          });
        }
      }

      return disks;
    } catch (error) {
      console.error('Failed to get Unix disk usage:', error);
      return [];
    }
  }

  // Scan file (platform-specific implementation)
  async scanFile(filePath) {
    const stats = await fs.stat(filePath);
    const fileSize = stats.size;
    const isExecutable = this.isExecutableFile(filePath);
    
    // Read file header for signature detection
    const buffer = Buffer.alloc(Math.min(fileSize, 8192));
    const fd = await fs.open(filePath, 'r');
    await fd.read(buffer, 0, buffer.length, 0);
    await fd.close();

    return {
      filePath,
      fileSize,
      isExecutable,
      header: buffer.slice(0, 100).toString('hex'),
      platform: this.platform,
      suspicious: this.checkSuspiciousPatterns(buffer, filePath),
    };
  }

  isExecutableFile(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    
    if (this.isWindows) {
      return ['.exe', '.dll', '.bat', '.cmd', '.vbs', '.ps1', '.msi'].includes(ext);
    } else if (this.isMacOS) {
      return ['.app', '.dmg', '.pkg', '.sh', '.command'].some(e => filePath.includes(e));
    } else {
      return ['.sh', '.bin', '.run', '.elf'].includes(ext) || ext === '';
    }
  }

  checkSuspiciousPatterns(buffer, filePath) {
    const suspiciousIndicators = [];
    const content = buffer.toString('utf8', 0, Math.min(buffer.length, 1000));

    // Check for common malware signatures
    const patterns = [
      { pattern: /cmd\.exe.*\/c/i, description: 'Command execution' },
      { pattern: /powershell.*-enc/i, description: 'Encoded PowerShell' },
      { pattern: /eval\s*\(/i, description: 'Code evaluation' },
      { pattern: /WScript\.Shell/i, description: 'Script execution' },
      { pattern: /CreateObject\(/i, description: 'Object creation' },
    ];

    patterns.forEach(({ pattern, description }) => {
      if (pattern.test(content)) {
        suspiciousIndicators.push(description);
      }
    });

    return suspiciousIndicators;
  }

  // Get system information
  getSystemInfo() {
    return {
      platform: this.platform,
      architecture: os.arch(),
      hostname: os.hostname(),
      cpus: os.cpus().length,
      totalMemory: os.totalmem(),
      freeMemory: os.freemem(),
      uptime: os.uptime(),
      osType: os.type(),
      osRelease: os.release(),
      osVersion: os.version(),
    };
  }
}

module.exports = new PlatformAdapter();
