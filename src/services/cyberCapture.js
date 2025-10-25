/**
 * CyberCapture - Cloud-based Sandbox Analysis
 * Intercepts unknown/suspicious files and analyzes them in a safe environment
 */

import CryptoJS from 'crypto-js';

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
 * Capture and analyze file in sandbox
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
    behaviors: [],
    networkActivity: [],
    fileActivity: [],
    registryActivity: [],
    processActivity: []
  };

  activeSandboxSessions.push(session);
  sandboxQueue.push(session);

  console.log(`🔒 CyberCapture: Analyzing ${session.fileName} in sandbox...`);

  // Simulate sandbox analysis
  return new Promise((resolve) => {
    setTimeout(() => {
      const result = performSandboxAnalysis(session);
      session.status = 'completed';
      session.endTime = new Date();
      session.threat = result.threat;
      session.confidence = result.confidence;
      session.behaviors = result.behaviors;
      session.networkActivity = result.networkActivity;
      session.fileActivity = result.fileActivity;
      session.registryActivity = result.registryActivity;
      session.processActivity = result.processActivity;

      // Remove from active sessions
      activeSandboxSessions = activeSandboxSessions.filter(s => s.id !== captureId);
      
      // Add to history
      captureHistory.unshift(session);
      if (captureHistory.length > 100) {
        captureHistory.pop();
      }

      resolve(result);
    }, 3000 + Math.random() * 2000); // 3-5 seconds analysis
  });
}

/**
 * Perform sandbox analysis on file
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
 * Get CyberCapture statistics
 */
export function getCaptureStats() {
  const total = captureHistory.length;
  const malicious = captureHistory.filter(s => s.threat && s.threat.type === 'MALWARE').length;
  const suspicious = captureHistory.filter(s => s.threat && s.threat.type === 'SUSPICIOUS').length;
  const clean = captureHistory.filter(s => !s.threat).length;

  return {
    enabled: isEnabled,
    totalAnalyzed: total,
    maliciousDetected: malicious,
    suspiciousDetected: suspicious,
    cleanFiles: clean,
    activeAnalysis: activeSandboxSessions.length,
    queuedFiles: sandboxQueue.length,
    detectionRate: total > 0 ? ((malicious + suspicious) / total * 100).toFixed(1) : 0
  };
}

/**
 * Get capture history
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
    behaviorCount: session.behaviors.length,
    verdict: session.threat ? 'malicious' : 'clean'
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
 * Export current state for persistence
 */
export function exportCaptureState() {
  return {
    enabled: isEnabled,
    history: captureHistory,
    stats: getCaptureStats()
  };
}

/**
 * Import state from persistence
 */
export function importCaptureState(state) {
  if (state) {
    isEnabled = state.enabled !== undefined ? state.enabled : true;
    captureHistory = state.history || [];
  }
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
  importCaptureState
};
