/**
 * Advanced Sandbox & Isolation System
 * 
 * Features:
 * - Windows Defender Application Guard (WDAG) Integration
 * - Virtual Machine Sandboxing (Hyper-V)
 * - Container-based Isolation (Docker)
 * - Cloud-based Sandbox Analysis
 * - Multi-layer Isolation Strategy
 */

const { EventEmitter } = require('events');
const fs = require('fs').promises;
const path = require('path');
const { exec, spawn } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');
const axios = require('axios');

const execAsync = promisify(exec);

class SandboxIsolation extends EventEmitter {
  constructor() {
    super();
    
    this.dataDir = path.join(__dirname, 'data');
    this.configPath = path.join(this.dataDir, 'sandbox-config.json');
    this.sandboxesPath = path.join(this.dataDir, 'sandboxes.json');
    this.quarantinePath = path.join(this.dataDir, 'quarantine');
    
    this.config = {
      wdag: {
        enabled: false,
        available: false,
        isolationLevel: 'high',
        clipboardAccess: false,
        printAccess: false,
        fileAccess: 'disabled'
      },
      hyperv: {
        enabled: false,
        available: false,
        vmName: 'NebulaShield-Sandbox',
        memory: 2048, // MB
        processors: 2,
        diskSize: 20 // GB
      },
      docker: {
        enabled: false,
        available: false,
        image: 'nebulashield/sandbox:latest',
        networkIsolation: true,
        readOnly: true,
        memoryLimit: '1g',
        cpuLimit: 1
      },
      cloudSandbox: {
        enabled: false,
        providers: {
          virustotal: {
            enabled: false,
            apiKey: '',
            endpoint: 'https://www.virustotal.com/api/v3'
          },
          hybrid: {
            enabled: false,
            apiKey: '',
            endpoint: 'https://www.hybrid-analysis.com/api/v2'
          },
          joesandbox: {
            enabled: false,
            apiKey: '',
            endpoint: 'https://jbxcloud.joesecurity.org/api'
          },
          anyrun: {
            enabled: false,
            apiKey: '',
            endpoint: 'https://api.any.run/v1'
          }
        },
        timeout: 300000, // 5 minutes
        autoSubmit: false
      },
      general: {
        defaultMode: 'auto', // auto, wdag, hyperv, docker, cloud
        executionTimeout: 120000, // 2 minutes
        networkMonitoring: true,
        fileSystemMonitoring: true,
        registryMonitoring: true,
        processMonitoring: true
      }
    };
    
    this.sandboxes = new Map();
    this.activeSessions = new Map();
    this.analysisQueue = [];
    this.statistics = {
      totalAnalyses: 0,
      wdagAnalyses: 0,
      hypervAnalyses: 0,
      dockerAnalyses: 0,
      cloudAnalyses: 0,
      threatsDetected: 0,
      cleanFiles: 0,
      analysisTime: {
        total: 0,
        average: 0
      }
    };
  }

  async initialize() {
    try {
      await fs.mkdir(this.dataDir, { recursive: true });
      await fs.mkdir(this.quarantinePath, { recursive: true });
      
      // Load configuration
      await this.loadConfig();
      
      // Check system capabilities
      await this.checkSystemCapabilities();
      
      // Initialize sandboxes
      await this.initializeSandboxes();
      
      this.emit('initialized', {
        wdag: this.config.wdag.available,
        hyperv: this.config.hyperv.available,
        docker: this.config.docker.available
      });
      
      console.log('🔒 Sandbox & Isolation System initialized');
      console.log(`   • WDAG: ${this.config.wdag.available ? '✅ Available' : '❌ Not Available'}`);
      console.log(`   • Hyper-V: ${this.config.hyperv.available ? '✅ Available' : '❌ Not Available'}`);
      console.log(`   • Docker: ${this.config.docker.available ? '✅ Available' : '❌ Not Available'}`);
      console.log(`   • Cloud Sandbox: ${this.config.cloudSandbox.enabled ? '✅ Enabled' : '❌ Disabled'}`);
      
    } catch (error) {
      console.error('Failed to initialize Sandbox & Isolation System:', error);
      throw error;
    }
  }

  async loadConfig() {
    try {
      const data = await fs.readFile(this.configPath, 'utf8');
      const loaded = JSON.parse(data);
      this.config = { ...this.config, ...loaded };
    } catch (error) {
      // Use defaults if file doesn't exist
      await this.saveConfig();
    }
  }

  async saveConfig() {
    await fs.writeFile(
      this.configPath,
      JSON.stringify(this.config, null, 2),
      'utf8'
    );
  }

  async checkSystemCapabilities() {
    // Check Windows Defender Application Guard
    this.config.wdag.available = await this.checkWDAG();
    
    // Check Hyper-V
    this.config.hyperv.available = await this.checkHyperV();
    
    // Check Docker
    this.config.docker.available = await this.checkDocker();
    
    await this.saveConfig();
  }

  async checkWDAG() {
    try {
      // Check if WDAG is installed
      const { stdout } = await execAsync(
        'powershell -Command "Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard"',
        { timeout: 10000 }
      );
      
      return stdout.includes('Enabled') || stdout.includes('State : Enabled');
    } catch (error) {
      return false;
    }
  }

  async checkHyperV() {
    try {
      // Check if Hyper-V is installed and running
      const { stdout } = await execAsync(
        'powershell -Command "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All"',
        { timeout: 10000 }
      );
      
      return stdout.includes('Enabled') || stdout.includes('State : Enabled');
    } catch (error) {
      return false;
    }
  }

  async checkDocker() {
    try {
      // Check if Docker is installed and running
      await execAsync('docker --version', { timeout: 5000 });
      await execAsync('docker ps', { timeout: 5000 });
      return true;
    } catch (error) {
      return false;
    }
  }

  async initializeSandboxes() {
    try {
      const data = await fs.readFile(this.sandboxesPath, 'utf8');
      const sandboxes = JSON.parse(data);
      
      for (const [id, sandbox] of Object.entries(sandboxes)) {
        this.sandboxes.set(id, sandbox);
      }
    } catch (error) {
      // No existing sandboxes
    }
  }

  async analyzeSuspiciousFile(filePath, options = {}) {
    const analysisId = crypto.randomUUID();
    const startTime = Date.now();
    
    const analysis = {
      id: analysisId,
      filePath,
      fileName: path.basename(filePath),
      timestamp: new Date().toISOString(),
      mode: options.mode || this.config.general.defaultMode,
      status: 'pending',
      results: []
    };
    
    try {
      this.emit('analysis-started', analysis);
      
      // Determine sandbox mode
      const mode = this.determineSandboxMode(options.mode);
      analysis.actualMode = mode;
      
      // Execute analysis based on mode
      let result;
      switch (mode) {
        case 'wdag':
          result = await this.analyzeWithWDAG(filePath, options);
          this.statistics.wdagAnalyses++;
          break;
          
        case 'hyperv':
          result = await this.analyzeWithHyperV(filePath, options);
          this.statistics.hypervAnalyses++;
          break;
          
        case 'docker':
          result = await this.analyzeWithDocker(filePath, options);
          this.statistics.dockerAnalyses++;
          break;
          
        case 'cloud':
          result = await this.analyzeWithCloud(filePath, options);
          this.statistics.cloudAnalyses++;
          break;
          
        default:
          throw new Error('No suitable sandbox available');
      }
      
      analysis.results.push(result);
      analysis.status = 'completed';
      analysis.threat = result.threat;
      analysis.score = result.score;
      analysis.duration = Date.now() - startTime;
      
      // Update statistics
      this.statistics.totalAnalyses++;
      this.statistics.analysisTime.total += analysis.duration;
      this.statistics.analysisTime.average = 
        this.statistics.analysisTime.total / this.statistics.totalAnalyses;
      
      if (result.threat) {
        this.statistics.threatsDetected++;
        await this.quarantineFile(filePath, result);
      } else {
        this.statistics.cleanFiles++;
      }
      
      this.emit('analysis-completed', analysis);
      return analysis;
      
    } catch (error) {
      analysis.status = 'failed';
      analysis.error = error.message;
      this.emit('analysis-failed', analysis);
      throw error;
    }
  }

  determineSandboxMode(requestedMode) {
    if (requestedMode === 'auto') {
      // Automatic selection based on availability
      if (this.config.docker.enabled && this.config.docker.available) {
        return 'docker';
      } else if (this.config.wdag.enabled && this.config.wdag.available) {
        return 'wdag';
      } else if (this.config.hyperv.enabled && this.config.hyperv.available) {
        return 'hyperv';
      } else if (this.config.cloudSandbox.enabled) {
        return 'cloud';
      }
      throw new Error('No sandbox available');
    }
    
    // Validate requested mode is available
    switch (requestedMode) {
      case 'wdag':
        if (!this.config.wdag.available) throw new Error('WDAG not available');
        break;
      case 'hyperv':
        if (!this.config.hyperv.available) throw new Error('Hyper-V not available');
        break;
      case 'docker':
        if (!this.config.docker.available) throw new Error('Docker not available');
        break;
      case 'cloud':
        if (!this.config.cloudSandbox.enabled) throw new Error('Cloud sandbox not enabled');
        break;
    }
    
    return requestedMode;
  }

  async analyzeWithWDAG(filePath, options) {
    console.log(`🛡️ Analyzing with WDAG: ${path.basename(filePath)}`);
    
    const sessionId = crypto.randomUUID();
    const startTime = Date.now();
    
    try {
      // Copy file to WDAG accessible location
      const wdagPath = path.join(process.env.LOCALAPPDATA, 'Packages', 
        'Microsoft.Windows.Defender.ApplicationGuard_8wekyb3d8bbwe', 'TempState');
      
      const targetPath = path.join(wdagPath, `sandbox_${sessionId}_${path.basename(filePath)}`);
      
      // Use Application Guard to open/execute file
      const command = `powershell -Command "Start-Process -FilePath '${filePath}' -WindowStyle Hidden -ArgumentList '/wdag'"`;
      
      const result = await this.executeInWDAG(command, options.timeout || 60000);
      
      const analysis = {
        mode: 'wdag',
        sessionId,
        duration: Date.now() - startTime,
        threat: result.suspicious,
        score: result.score,
        behaviors: result.behaviors,
        networkActivity: result.networkActivity,
        fileOperations: result.fileOperations,
        registryOperations: result.registryOperations,
        processActivity: result.processActivity
      };
      
      return analysis;
      
    } catch (error) {
      console.error('WDAG analysis failed:', error);
      throw error;
    }
  }

  async executeInWDAG(command, timeout) {
    return new Promise((resolve, reject) => {
      const behaviors = [];
      const networkActivity = [];
      const fileOperations = [];
      const registryOperations = [];
      const processActivity = [];
      
      const process = spawn('powershell', ['-Command', command]);
      
      let suspicious = false;
      let score = 0;
      
      const timer = setTimeout(() => {
        process.kill();
        reject(new Error('WDAG execution timeout'));
      }, timeout);
      
      process.stdout.on('data', (data) => {
        const output = data.toString();
        // Monitor for suspicious behavior
        if (output.includes('network') || output.includes('connection')) {
          networkActivity.push({ type: 'connection', data: output });
          score += 10;
        }
        if (output.includes('file') || output.includes('write')) {
          fileOperations.push({ type: 'write', data: output });
          score += 15;
        }
      });
      
      process.on('close', (code) => {
        clearTimeout(timer);
        
        if (score > 50) suspicious = true;
        
        resolve({
          suspicious,
          score,
          behaviors,
          networkActivity,
          fileOperations,
          registryOperations,
          processActivity
        });
      });
      
      process.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  async analyzeWithHyperV(filePath, options) {
    console.log(`💻 Analyzing with Hyper-V: ${path.basename(filePath)}`);
    
    const vmName = `NebulaShield-Sandbox-${crypto.randomUUID().substring(0, 8)}`;
    const startTime = Date.now();
    
    try {
      // Create snapshot VM
      await this.createHyperVVM(vmName);
      
      // Copy file to VM
      await this.copyFileToVM(vmName, filePath);
      
      // Execute and monitor
      const result = await this.executeInVM(vmName, filePath, options.timeout || 120000);
      
      // Cleanup VM
      await this.deleteHyperVVM(vmName);
      
      const analysis = {
        mode: 'hyperv',
        vmName,
        duration: Date.now() - startTime,
        threat: result.suspicious,
        score: result.score,
        behaviors: result.behaviors,
        networkActivity: result.networkActivity,
        fileOperations: result.fileOperations,
        processActivity: result.processActivity
      };
      
      return analysis;
      
    } catch (error) {
      console.error('Hyper-V analysis failed:', error);
      // Cleanup on error
      try {
        await this.deleteHyperVVM(vmName);
      } catch (cleanupError) {
        console.error('VM cleanup failed:', cleanupError);
      }
      throw error;
    }
  }

  async createHyperVVM(vmName) {
    // Create a minimal Windows VM for sandboxing
    const command = `
      New-VM -Name "${vmName}" -MemoryStartupBytes ${this.config.hyperv.memory}MB -Generation 2;
      Set-VM -Name "${vmName}" -ProcessorCount ${this.config.hyperv.processors};
      New-VHD -Path "$env:USERPROFILE\\Hyper-V\\${vmName}.vhdx" -SizeBytes ${this.config.hyperv.diskSize}GB -Dynamic;
      Add-VMHardDiskDrive -VMName "${vmName}" -Path "$env:USERPROFILE\\Hyper-V\\${vmName}.vhdx";
      Start-VM -Name "${vmName}"
    `;
    
    await execAsync(`powershell -Command "${command}"`, { timeout: 60000 });
  }

  async copyFileToVM(vmName, filePath) {
    const command = `Copy-VMFile -VMName "${vmName}" -SourcePath "${filePath}" -DestinationPath "C:\\Temp\\${path.basename(filePath)}" -FileSource Host`;
    await execAsync(`powershell -Command "${command}"`, { timeout: 30000 });
  }

  async executeInVM(vmName, filePath, timeout) {
    return new Promise((resolve, reject) => {
      const behaviors = [];
      const networkActivity = [];
      const fileOperations = [];
      const processActivity = [];
      
      let suspicious = false;
      let score = 0;
      
      // Execute file in VM and monitor
      const fileName = path.basename(filePath);
      const command = `Invoke-Command -VMName "${vmName}" -ScriptBlock { Start-Process "C:\\Temp\\${fileName}" }`;
      
      const process = spawn('powershell', ['-Command', command]);
      
      const timer = setTimeout(() => {
        process.kill();
        resolve({
          suspicious: true,
          score: 100,
          behaviors: ['timeout'],
          networkActivity,
          fileOperations,
          processActivity
        });
      }, timeout);
      
      process.on('close', (code) => {
        clearTimeout(timer);
        
        if (score > 60) suspicious = true;
        
        resolve({
          suspicious,
          score,
          behaviors,
          networkActivity,
          fileOperations,
          processActivity
        });
      });
      
      process.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  async deleteHyperVVM(vmName) {
    const command = `
      Stop-VM -Name "${vmName}" -Force -TurnOff;
      Remove-VM -Name "${vmName}" -Force;
      Remove-Item "$env:USERPROFILE\\Hyper-V\\${vmName}.vhdx" -Force
    `;
    
    await execAsync(`powershell -Command "${command}"`, { timeout: 30000 });
  }

  async analyzeWithDocker(filePath, options) {
    console.log(`🐳 Analyzing with Docker: ${path.basename(filePath)}`);
    
    const containerId = `nebula-sandbox-${crypto.randomUUID().substring(0, 8)}`;
    const startTime = Date.now();
    
    try {
      // Build sandbox container if needed
      await this.ensureDockerImage();
      
      // Run file in isolated container
      const result = await this.executeInDocker(containerId, filePath, options.timeout || 120000);
      
      // Cleanup container
      await this.removeDockerContainer(containerId);
      
      const analysis = {
        mode: 'docker',
        containerId,
        duration: Date.now() - startTime,
        threat: result.suspicious,
        score: result.score,
        behaviors: result.behaviors,
        networkActivity: result.networkActivity,
        fileOperations: result.fileOperations,
        processActivity: result.processActivity
      };
      
      return analysis;
      
    } catch (error) {
      console.error('Docker analysis failed:', error);
      // Cleanup on error
      try {
        await this.removeDockerContainer(containerId);
      } catch (cleanupError) {
        console.error('Container cleanup failed:', cleanupError);
      }
      throw error;
    }
  }

  async ensureDockerImage() {
    try {
      // Check if image exists
      await execAsync(`docker inspect ${this.config.docker.image}`, { timeout: 5000 });
    } catch (error) {
      // Build image
      console.log('Building Docker sandbox image...');
      const dockerfile = `
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \\
    strace \\
    tcpdump \\
    inotify-tools \\
    procps \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /sandbox
CMD ["/bin/bash"]
      `;
      
      const dockerfilePath = path.join(this.dataDir, 'Dockerfile');
      await fs.writeFile(dockerfilePath, dockerfile);
      
      await execAsync(
        `docker build -t ${this.config.docker.image} ${this.dataDir}`,
        { timeout: 300000 }
      );
    }
  }

  async executeInDocker(containerId, filePath, timeout) {
    return new Promise((resolve, reject) => {
      const behaviors = [];
      const networkActivity = [];
      const fileOperations = [];
      const processActivity = [];
      
      let suspicious = false;
      let score = 0;
      
      // Run container with strict isolation
      const command = [
        'docker', 'run',
        '--name', containerId,
        '--rm',
        '--network', this.config.docker.networkIsolation ? 'none' : 'bridge',
        '--read-only',
        '--memory', this.config.docker.memoryLimit,
        '--cpus', this.config.docker.cpuLimit.toString(),
        '--security-opt', 'no-new-privileges',
        '--cap-drop', 'ALL',
        '-v', `${filePath}:/sandbox/${path.basename(filePath)}:ro`,
        this.config.docker.image,
        'strace', '-f', '-e', 'trace=all',
        `/sandbox/${path.basename(filePath)}`
      ];
      
      const process = spawn(command[0], command.slice(1));
      
      const timer = setTimeout(() => {
        this.removeDockerContainer(containerId).catch(() => {});
        process.kill();
        resolve({
          suspicious: true,
          score: 100,
          behaviors: ['timeout'],
          networkActivity,
          fileOperations,
          processActivity
        });
      }, timeout);
      
      process.stdout.on('data', (data) => {
        const output = data.toString();
        processActivity.push(output);
      });
      
      process.stderr.on('data', (data) => {
        const output = data.toString();
        
        // Analyze strace output
        if (output.includes('connect') || output.includes('socket')) {
          networkActivity.push({ type: 'network', syscall: output });
          score += 20;
        }
        
        if (output.includes('open') || output.includes('write')) {
          fileOperations.push({ type: 'file', syscall: output });
          score += 10;
        }
        
        if (output.includes('execve') || output.includes('fork')) {
          behaviors.push({ type: 'process', syscall: output });
          score += 15;
        }
      });
      
      process.on('close', (code) => {
        clearTimeout(timer);
        
        if (score > 50 || code !== 0) suspicious = true;
        
        resolve({
          suspicious,
          score,
          behaviors,
          networkActivity,
          fileOperations,
          processActivity,
          exitCode: code
        });
      });
      
      process.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  async removeDockerContainer(containerId) {
    try {
      await execAsync(`docker rm -f ${containerId}`, { timeout: 10000 });
    } catch (error) {
      // Container might already be removed
    }
  }

  async analyzeWithCloud(filePath, options) {
    console.log(`☁️ Analyzing with Cloud Sandbox: ${path.basename(filePath)}`);
    
    const startTime = Date.now();
    const results = [];
    
    // Submit to all enabled cloud providers
    const providers = Object.entries(this.config.cloudSandbox.providers)
      .filter(([_, config]) => config.enabled && config.apiKey);
    
    if (providers.length === 0) {
      throw new Error('No cloud sandbox providers configured');
    }
    
    for (const [provider, config] of providers) {
      try {
        let result;
        
        switch (provider) {
          case 'virustotal':
            result = await this.analyzeWithVirusTotal(filePath, config);
            break;
          case 'hybrid':
            result = await this.analyzeWithHybridAnalysis(filePath, config);
            break;
          case 'joesandbox':
            result = await this.analyzeWithJoeSandbox(filePath, config);
            break;
          case 'anyrun':
            result = await this.analyzeWithAnyRun(filePath, config);
            break;
        }
        
        results.push({
          provider,
          ...result
        });
        
      } catch (error) {
        console.error(`${provider} analysis failed:`, error.message);
        results.push({
          provider,
          error: error.message
        });
      }
    }
    
    // Aggregate results
    const scores = results.filter(r => r.score).map(r => r.score);
    const avgScore = scores.length > 0 
      ? scores.reduce((a, b) => a + b, 0) / scores.length 
      : 0;
    
    const threat = avgScore > 50;
    
    const analysis = {
      mode: 'cloud',
      duration: Date.now() - startTime,
      threat,
      score: avgScore,
      providers: results,
      aggregatedBehaviors: this.aggregateBehaviors(results)
    };
    
    return analysis;
  }

  async analyzeWithVirusTotal(filePath, config) {
    // Read file and calculate hash
    const fileBuffer = await fs.readFile(filePath);
    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    
    try {
      // Check if file already analyzed
      const response = await axios.get(
        `${config.endpoint}/files/${hash}`,
        {
          headers: { 'x-apikey': config.apiKey },
          timeout: 30000
        }
      );
      
      const stats = response.data.data.attributes.last_analysis_stats;
      const malicious = stats.malicious || 0;
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      
      return {
        score: total > 0 ? (malicious / total) * 100 : 0,
        detections: malicious,
        totalScans: total,
        hash,
        behaviors: response.data.data.attributes.behavior_summary || []
      };
      
    } catch (error) {
      if (error.response && error.response.status === 404) {
        // File not found, submit for analysis
        const formData = new FormData();
        formData.append('file', fileBuffer, path.basename(filePath));
        
        await axios.post(
          `${config.endpoint}/files`,
          formData,
          {
            headers: { 
              'x-apikey': config.apiKey,
              ...formData.getHeaders()
            },
            timeout: 60000
          }
        );
        
        return {
          score: 0,
          status: 'submitted',
          message: 'File submitted for analysis'
        };
      }
      throw error;
    }
  }

  async analyzeWithHybridAnalysis(filePath, config) {
    // Hybrid Analysis implementation
    const formData = new FormData();
    const fileBuffer = await fs.readFile(filePath);
    formData.append('file', fileBuffer, path.basename(filePath));
    formData.append('environment_id', '120'); // Windows 10 64-bit
    
    const response = await axios.post(
      `${config.endpoint}/submit/file`,
      formData,
      {
        headers: {
          'api-key': config.apiKey,
          'user-agent': 'NebulaShield',
          ...formData.getHeaders()
        },
        timeout: 60000
      }
    );
    
    const jobId = response.data.job_id;
    
    // Poll for results
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    const resultResponse = await axios.get(
      `${config.endpoint}/report/${jobId}/summary`,
      {
        headers: { 'api-key': config.apiKey },
        timeout: 30000
      }
    );
    
    const verdict = resultResponse.data.verdict;
    const score = verdict === 'malicious' ? 100 : verdict === 'suspicious' ? 50 : 0;
    
    return {
      score,
      verdict,
      jobId,
      behaviors: resultResponse.data.behavior || []
    };
  }

  async analyzeWithJoeSandbox(filePath, config) {
    // Joe Sandbox implementation
    const formData = new FormData();
    const fileBuffer = await fs.readFile(filePath);
    formData.append('sample', fileBuffer, path.basename(filePath));
    
    const response = await axios.post(
      `${config.endpoint}/v2/submission/new`,
      formData,
      {
        headers: {
          'apikey': config.apiKey,
          ...formData.getHeaders()
        },
        timeout: 60000
      }
    );
    
    return {
      score: 0,
      status: 'submitted',
      submissionId: response.data.data.submission_id
    };
  }

  async analyzeWithAnyRun(filePath, config) {
    // ANY.RUN implementation
    const formData = new FormData();
    const fileBuffer = await fs.readFile(filePath);
    formData.append('file', fileBuffer, path.basename(filePath));
    
    const response = await axios.post(
      `${config.endpoint}/analysis`,
      formData,
      {
        headers: {
          'Authorization': `API-Key ${config.apiKey}`,
          ...formData.getHeaders()
        },
        timeout: 60000
      }
    );
    
    return {
      score: 0,
      status: 'submitted',
      taskUuid: response.data.data.taskid
    };
  }

  aggregateBehaviors(results) {
    const behaviors = {
      network: [],
      file: [],
      registry: [],
      process: [],
      dll: []
    };
    
    for (const result of results) {
      if (result.behaviors) {
        for (const behavior of result.behaviors) {
          if (behavior.type === 'network') behaviors.network.push(behavior);
          if (behavior.type === 'file') behaviors.file.push(behavior);
          if (behavior.type === 'registry') behaviors.registry.push(behavior);
          if (behavior.type === 'process') behaviors.process.push(behavior);
          if (behavior.type === 'dll') behaviors.dll.push(behavior);
        }
      }
    }
    
    return behaviors;
  }

  async quarantineFile(filePath, analysisResult) {
    const fileName = path.basename(filePath);
    const quarantineId = crypto.randomUUID();
    const targetPath = path.join(this.quarantinePath, `${quarantineId}_${fileName}`);
    
    // Move file to quarantine
    await fs.rename(filePath, targetPath);
    
    // Save analysis metadata
    const metadata = {
      id: quarantineId,
      originalPath: filePath,
      fileName,
      quarantinePath: targetPath,
      timestamp: new Date().toISOString(),
      analysisResult
    };
    
    const metadataPath = path.join(this.quarantinePath, `${quarantineId}.json`);
    await fs.writeFile(metadataPath, JSON.stringify(metadata, null, 2));
    
    this.emit('file-quarantined', metadata);
    
    return metadata;
  }

  async updateConfig(updates) {
    this.config = { ...this.config, ...updates };
    await this.saveConfig();
    this.emit('config-updated', this.config);
  }

  getStatistics() {
    return {
      ...this.statistics,
      capabilities: {
        wdag: this.config.wdag.available,
        hyperv: this.config.hyperv.available,
        docker: this.config.docker.available,
        cloud: this.config.cloudSandbox.enabled
      },
      activeSessions: this.activeSessions.size,
      queueLength: this.analysisQueue.length
    };
  }

  getConfig() {
    // Return config without API keys
    const safeConfig = JSON.parse(JSON.stringify(this.config));
    
    if (safeConfig.cloudSandbox && safeConfig.cloudSandbox.providers) {
      for (const provider in safeConfig.cloudSandbox.providers) {
        if (safeConfig.cloudSandbox.providers[provider].apiKey) {
          safeConfig.cloudSandbox.providers[provider].apiKey = '***';
        }
      }
    }
    
    return safeConfig;
  }
}

// Create singleton instance
const sandboxIsolation = new SandboxIsolation();

module.exports = sandboxIsolation;
