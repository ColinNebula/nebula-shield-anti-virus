const { exec, execSync } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const si = require('systeminformation');
const { getDiskInfo } = require('node-disk-info');
const os = require('os');

class RealSystemMonitor {
    constructor() {
        this.isWindows = process.platform === 'win32';
        this.cache = {
            processes: { data: null, timestamp: 0 },
            cpu: { data: null, timestamp: 0 },
            temp: { data: null, timestamp: 0 },
            disk: { data: null, timestamp: 0 },
        };
        this.cacheTimeout = 2000; // 2 seconds cache
    }

    /**
     * Get real CPU usage and information
     */
    async getCpuInfo() {
        const now = Date.now();
        if (this.cache.cpu.data && now - this.cache.cpu.timestamp < this.cacheTimeout) {
            return this.cache.cpu.data;
        }

        try {
            const [cpuLoad, cpuInfo, cpuTemp] = await Promise.all([
                si.currentLoad(),
                si.cpu(),
                si.cpuTemperature().catch(() => ({ main: null })),
            ]);

            const data = {
                usage: Math.round(cpuLoad.currentLoad),
                cores: cpuInfo.cores,
                physicalCores: cpuInfo.physicalCores,
                speed: cpuInfo.speed,
                model: cpuInfo.manufacturer ? `${cpuInfo.manufacturer} ${cpuInfo.brand}` : cpuInfo.brand,
                temperature: cpuTemp.main || null,
            };

            this.cache.cpu = { data, timestamp: now };
            return data;
        } catch (error) {
            console.error('Error getting CPU info:', error);
            const cpus = os.cpus();
            return {
                usage: 0,
                cores: cpus.length,
                physicalCores: cpus.length,
                speed: cpus[0]?.speed || 0,
                model: cpus[0]?.model || 'Unknown',
                temperature: null,
            };
        }
    }

    /**
     * Get real memory usage
     */
    async getMemoryInfo() {
        try {
            const mem = await si.mem();
            return {
                total: mem.total,
                free: mem.free,
                used: mem.used,
                active: mem.active,
                usagePercent: Math.round((mem.used / mem.total) * 100),
            };
        } catch (error) {
            console.error('Error getting memory info:', error);
            const totalMem = os.totalmem();
            const freeMem = os.freemem();
            const usedMem = totalMem - freeMem;
            return {
                total: totalMem,
                free: freeMem,
                used: usedMem,
                active: usedMem,
                usagePercent: Math.round((usedMem / totalMem) * 100),
            };
        }
    }

    /**
     * Get real disk usage for all drives
     */
    async getDiskInfo() {
        const now = Date.now();
        if (this.cache.disk.data && now - this.cache.disk.timestamp < this.cacheTimeout) {
            return this.cache.disk.data;
        }

        try {
            const fsSize = await si.fsSize();
            
            const diskData = fsSize.map(disk => ({
                fs: disk.fs,
                type: disk.type,
                size: disk.size,
                used: disk.used,
                available: disk.available,
                usagePercent: Math.round(disk.use),
                mount: disk.mount,
            }));

            const totalSize = diskData.reduce((sum, d) => sum + d.size, 0);
            const totalUsed = diskData.reduce((sum, d) => sum + d.used, 0);
            const totalFree = diskData.reduce((sum, d) => sum + d.available, 0);

            const data = {
                drives: diskData,
                total: totalSize,
                used: totalUsed,
                free: totalFree,
                usagePercent: Math.round((totalUsed / totalSize) * 100),
            };

            this.cache.disk = { data, timestamp: now };
            return data;
        } catch (error) {
            console.error('Error getting disk info:', error);
            return {
                drives: [],
                total: 0,
                used: 0,
                free: 0,
                usagePercent: 0,
            };
        }
    }

    /**
     * Get CPU temperature
     */
    async getCpuTemperature() {
        const now = Date.now();
        if (this.cache.temp.data !== null && now - this.cache.temp.timestamp < this.cacheTimeout) {
            return this.cache.temp.data;
        }

        try {
            const temp = await si.cpuTemperature();
            const temperature = temp.main || temp.max || null;
            this.cache.temp = { data: temperature, timestamp: now };
            return temperature;
        } catch (error) {
            // Temperature sensors may not be available on all systems
            return null;
        }
    }

    /**
     * Get network interfaces with real data
     */
    async getNetworkInfo() {
        try {
            const networkInterfaces = await si.networkInterfaces();
            return networkInterfaces
                .filter(iface => iface.ip4 && iface.ip4 !== '127.0.0.1')
                .map(iface => ({
                    name: iface.iface,
                    address: iface.ip4,
                    mac: iface.mac,
                    internal: iface.internal,
                    type: iface.type,
                }));
        } catch (error) {
            console.error('Error getting network info:', error);
            const networkInterfaces = os.networkInterfaces();
            const interfaces = [];
            for (const [name, iface] of Object.entries(networkInterfaces)) {
                const ipv4 = iface.find(i => i.family === 'IPv4' && !i.internal);
                if (ipv4) {
                    interfaces.push({ 
                        name, 
                        address: ipv4.address,
                        mac: ipv4.mac,
                        internal: ipv4.internal,
                        type: 'unknown',
                    });
                }
            }
            return interfaces;
        }
    }

    /**
     * Get comprehensive system health data
     */
    async getSystemHealth() {
        try {
            // Add timeout wrapper for each system call to prevent hanging
            const timeoutMs = 5000; // 5 seconds per call
            const withTimeout = (promise) => {
                return Promise.race([
                    promise,
                    new Promise((_, reject) => 
                        setTimeout(() => reject(new Error('Operation timeout')), timeoutMs)
                    )
                ]);
            };

            const [cpu, memory, disk, temp, network] = await Promise.all([
                withTimeout(this.getCpuInfo()).catch(() => ({ usage: 0, cores: 0, speed: 0, model: 'Unknown', temperature: null })),
                withTimeout(this.getMemoryInfo()).catch(() => ({ total: 0, free: 0, used: 0, usagePercent: 0 })),
                withTimeout(this.getDiskInfo()).catch(() => ({ total: 0, free: 0, used: 0, usagePercent: 0 })),
                withTimeout(this.getCpuTemperature()).catch(() => null),
                withTimeout(this.getNetworkInfo()).catch(() => []),
            ]);

            // Get process list for health endpoint with timeout
            let processes = [];
            try {
                const processList = await withTimeout(si.processes());
                processes = processList.list
                    .sort((a, b) => b.cpu - a.cpu)
                    .slice(0, 15)
                    .map(proc => ({
                        name: proc.name,
                        pid: proc.pid,
                        cpu: Math.round(proc.cpu * 10) / 10,
                        memory: proc.memRss,
                        status: proc.state,
                    }));
            } catch (error) {
                console.error('Error getting process list for health:', error);
            }

            // Calculate health score based on real metrics
            let healthScore = 100;
            if (cpu.usage > 80) healthScore -= 20;
            else if (cpu.usage > 60) healthScore -= 10;
            
            if (memory.usagePercent > 85) healthScore -= 20;
            else if (memory.usagePercent > 70) healthScore -= 10;
            
            if (disk.usagePercent > 90) healthScore -= 15;
            else if (disk.usagePercent > 75) healthScore -= 5;

            if (temp && temp > 80) healthScore -= 15;
            else if (temp && temp > 70) healthScore -= 5;
            
            let healthStatus = 'healthy';
            let healthMessage = 'All systems operating normally';
            if (healthScore < 70) {
                healthStatus = 'critical';
                healthMessage = 'Critical: System resources critically low';
            } else if (healthScore < 85) {
                healthStatus = 'warning';
                healthMessage = 'Warning: System resources running high';
            }

            return {
                success: true,
                health: {
                    status: healthStatus,
                    score: healthScore,
                    message: healthMessage,
                },
                cpu: {
                    ...cpu,
                    temperature: temp,
                },
                memory,
                disk,
                processes,
                network,
                timestamp: new Date().toISOString(),
            };
        } catch (error) {
            console.error('Error getting system health:', error);
            throw error;
        }
    }

    /**
     * Get real running processes from Windows
     */
    async getRunningProcesses() {
        const now = Date.now();
        if (this.cache.processes.data && now - this.cache.processes.timestamp < this.cacheTimeout) {
            return this.cache.processes.data;
        }

        try {
            // Try systeminformation first (cross-platform)
            const processes = await si.processes();
            
            const topProcesses = processes.list
                .sort((a, b) => b.cpu - a.cpu)
                .slice(0, 20)
                .map(proc => ({
                    name: proc.name,
                    pid: proc.pid,
                    parentPid: proc.parentPid,
                    path: proc.path || 'N/A',
                    commandLine: proc.command || '',
                    memoryUsage: proc.memRss * 1024, // Convert KB to bytes
                    cpu: Math.round(proc.cpu * 10) / 10,
                    threadCount: proc.threads || 0,
                    status: proc.state,
                    suspicious: this.checkSuspiciousProcess({
                        name: proc.name,
                        path: proc.path,
                        commandLine: proc.command
                    })
                }));

            this.cache.processes = { data: topProcesses, timestamp: now };
            return topProcesses;
        } catch (error) {
            console.error('systeminformation failed, trying Windows WMIC:', error.message);
            
            // Fallback to Windows WMIC if systeminformation fails
            if (!this.isWindows) {
                return [];
            }

            try {
                // Use WMIC for detailed process information
                const { stdout } = await execPromise(
                    'wmic process get Name,ProcessId,ExecutablePath,CommandLine,WorkingSetSize,ThreadCount,ParentProcessId /format:csv',
                    { maxBuffer: 1024 * 1024 * 10 } // 10MB buffer
                );
                
                const lines = stdout.trim().split('\n');
                
                const processes = lines.slice(1)
                    .filter(line => line.trim())
                    .map(line => {
                        const values = this.parseCSVLine(line);
                        if (values.length < 7) return null;
                        
                        const [node, cmdLine, exePath, name, parentPid, pid, threads, memory] = values;
                        
                        return {
                            name: (name || '').trim(),
                            pid: parseInt(pid) || 0,
                            parentPid: parseInt(parentPid) || 0,
                            path: (exePath || '').trim() || 'N/A',
                            commandLine: (cmdLine || '').trim(),
                            memoryUsage: parseInt(memory) || 0,
                            cpu: 0, // WMIC doesn't provide real-time CPU
                            threadCount: parseInt(threads) || 0,
                            status: 'running',
                            suspicious: this.checkSuspiciousProcess({
                                name, path: exePath, commandLine: cmdLine
                            })
                        };
                    })
                    .filter(p => p && p.name && p.pid);
                
                return processes;
            } catch (error) {
                console.error('Failed to get processes:', error.message);
                return [];
            }
        }
    }

    /**
     * Analyze specific process for threats
     */
    async analyzeProcess(pid) {
        try {
            const psCommand = `Get-Process -Id ${pid} | Select-Object Name,CPU,WorkingSet,Path,StartTime,Threads | ConvertTo-Json`;
            const { stdout } = await execPromise(`powershell "${psCommand}"`);
            
            const processInfo = JSON.parse(stdout);
            
            const suspicious = {
                highCPU: (processInfo.CPU || 0) > 80,
                noPath: !processInfo.Path,
                systemPath: processInfo.Path && processInfo.Path.includes('System32'),
                manyThreads: (processInfo.Threads && processInfo.Threads.Count > 50),
                recentlyStarted: processInfo.StartTime && 
                    (new Date() - new Date(processInfo.StartTime)) < 60000 // Started in last minute
            };
            
            return {
                pid,
                ...processInfo,
                suspicious,
                threatScore: this.calculateProcessThreatScore(suspicious),
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            return null;
        }
    }

    /**
     * Get network connections
     */
    async getNetworkConnections() {
        if (!this.isWindows) {
            throw new Error('Network monitoring only supported on Windows');
        }

        try {
            const { stdout } = await execPromise('netstat -ano -p TCP');
            
            const lines = stdout.split('\n').slice(4); // Skip headers
            const connections = lines
                .filter(line => line.trim())
                .map(line => {
                    const parts = line.trim().split(/\s+/);
                    if (parts.length < 5) return null;
                    
                    const [proto, localAddr, foreignAddr, state, pid] = parts;
                    const [localIP, localPort] = localAddr.split(':');
                    const [foreignIP, foreignPort] = foreignAddr.split(':');
                    
                    return {
                        protocol: proto,
                        localAddress: localIP,
                        localPort: parseInt(localPort) || 0,
                        remoteAddress: foreignIP === '0.0.0.0' ? '*' : foreignIP,
                        remotePort: parseInt(foreignPort) || 0,
                        state,
                        pid: parseInt(pid) || 0,
                        suspicious: this.checkSuspiciousConnection(foreignIP, parseInt(foreignPort)),
                        timestamp: new Date().toISOString()
                    };
                })
                .filter(conn => conn !== null);
            
            return connections;
        } catch (error) {
            console.error('Failed to get connections:', error.message);
            return [];
        }
    }

    /**
     * Get startup items from registry and startup folders
     */
    async getStartupItems() {
        if (!this.isWindows) {
            throw new Error('Startup management only supported on Windows');
        }

        const startupItems = [];
        
        // Registry paths to check
        const registryPaths = [
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
        ];
        
        // Query each registry path
        for (const regPath of registryPaths) {
            try {
                const { stdout } = await execPromise(`reg query "${regPath}"`);
                const items = this.parseRegistryOutput(stdout, regPath);
                startupItems.push(...items);
            } catch (error) {
                // Registry key might not exist or be empty
            }
        }
        
        // Get startup folder items
        try {
            const userStartup = process.env.APPDATA + '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup';
            const { stdout } = await execPromise(`dir "${userStartup}" /b`);
            
            const files = stdout.split('\n').filter(f => f.trim());
            files.forEach(file => {
                if (file.trim()) {
                    startupItems.push({
                        name: file.trim(),
                        location: 'Startup Folder (User)',
                        path: `${userStartup}\\${file.trim()}`,
                        enabled: true,
                        impact: this.assessImpact(file),
                        type: 'file'
                    });
                }
            });
        } catch (error) {
            // Startup folder might be empty
        }
        
        return startupItems;
    }

    /**
     * Get installed drivers
     */
    async getInstalledDrivers() {
        try {
            const psCommand = `Get-WindowsDriver -Online | Select-Object Driver,ClassName,ProviderName,Date,Version,DriverSignature | ConvertTo-Json`;
            const { stdout } = await execPromise(`powershell "${psCommand}"`, {
                maxBuffer: 1024 * 1024 * 10
            });
            
            let drivers = JSON.parse(stdout);
            drivers = Array.isArray(drivers) ? drivers : [drivers];
            
            return drivers.map(driver => ({
                name: driver.Driver,
                class: driver.ClassName,
                provider: driver.ProviderName,
                date: driver.Date,
                version: driver.Version,
                signed: driver.DriverSignature === 'Signed',
                status: 'installed',
                updateAvailable: false // Would need actual version checking
            }));
        } catch (error) {
            console.error('Failed to get drivers:', error.message);
            return [];
        }
    }

    // Helper methods

    parseCSVLine(line) {
        const result = [];
        let current = '';
        let inQuotes = false;
        
        for (let i = 0; i < line.length; i++) {
            const char = line[i];
            
            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                result.push(current.trim());
                current = '';
            } else {
                current += char;
            }
        }
        
        result.push(current.trim());
        return result;
    }

    parseRegistryOutput(output, regPath) {
        const items = [];
        const lines = output.split('\n');
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            
            if (line.includes('REG_SZ') || line.includes('REG_EXPAND_SZ')) {
                const match = line.match(/(\S+)\s+REG_[A-Z_]+\s+(.+)/);
                if (match) {
                    const [, name, command] = match;
                    items.push({
                        name: name.trim(),
                        location: regPath,
                        command: command.trim(),
                        enabled: true,
                        impact: this.assessImpact(name),
                        type: 'registry'
                    });
                }
            }
        }
        
        return items;
    }

    checkSuspiciousProcess({ name, path, commandLine }) {
        const suspicious = {
            score: 0,
            reasons: []
        };
        
        // Check for no path
        if (!path || path === 'N/A') {
            suspicious.score += 0.3;
            suspicious.reasons.push('No executable path');
        }
        
        // Check for suspicious names
        const suspiciousNames = /trojan|virus|malware|keylog|backdoor|rat|inject/i;
        if (suspiciousNames.test(name) || suspiciousNames.test(commandLine)) {
            suspicious.score += 0.6;
            suspicious.reasons.push('Suspicious name/command');
        }
        
        // Check for hidden processes
        if (commandLine && commandLine.includes('-hidden')) {
            suspicious.score += 0.4;
            suspicious.reasons.push('Hidden execution');
        }
        
        return {
            isSuspicious: suspicious.score > 0.5,
            score: Math.min(suspicious.score, 1.0),
            reasons: suspicious.reasons
        };
    }

    checkSuspiciousConnection(ip, port) {
        // Known suspicious ports
        const suspiciousPorts = [4444, 5555, 6666, 7777, 8888, 31337]; // Common backdoor ports
        
        // Check for suspicious IPs (non-local)
        const isExternal = ip !== '127.0.0.1' && 
                          ip !== 'localhost' && 
                          !ip.startsWith('192.168.') &&
                          !ip.startsWith('10.') &&
                          ip !== '*';
        
        const isSuspiciousPort = suspiciousPorts.includes(port);
        
        return {
            isSuspicious: isExternal && isSuspiciousPort,
            isExternal,
            isSuspiciousPort
        };
    }

    calculateProcessThreatScore(indicators) {
        let score = 0;
        
        if (indicators.highCPU) score += 0.2;
        if (indicators.noPath) score += 0.4;
        if (!indicators.systemPath && indicators.noPath) score += 0.3;
        if (indicators.manyThreads) score += 0.2;
        if (indicators.recentlyStarted) score += 0.1;
        
        return Math.min(score, 1.0);
    }

    assessImpact(programName) {
        const highImpact = /antivirus|security|firewall|windows|system|critical/i;
        const lowImpact = /updater|helper|notification|tooltip|tray/i;
        
        if (highImpact.test(programName)) return 'high';
        if (lowImpact.test(programName)) return 'low';
        return 'medium';
    }

    /**
     * Disable startup item
     */
    async disableStartupItem(name, location) {
        try {
            if (location.includes('HKLM') || location.includes('HKCU')) {
                await execPromise(`reg delete "${location}" /v "${name}" /f`);
                return { success: true, message: 'Startup item disabled' };
            } else if (location.includes('Startup Folder')) {
                // Would need to handle file deletion
                return { success: false, error: 'File deletion requires elevated permissions' };
            }
            
            return { success: false, error: 'Unsupported location' };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Block IP address via Windows Firewall
     */
    async blockIP(ipAddress, ruleName = null) {
        try {
            const name = ruleName || `Nebula Shield Block ${ipAddress}`;
            await execPromise(
                `netsh advfirewall firewall add rule name="${name}" dir=in action=block remoteip=${ipAddress}`
            );
            return { success: true, blocked: ipAddress, ruleName: name };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Terminate process
     */
    async terminateProcess(pid) {
        try {
            execSync(`taskkill /PID ${pid} /F`);
            return { success: true, pid };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
}

module.exports = new RealSystemMonitor();
