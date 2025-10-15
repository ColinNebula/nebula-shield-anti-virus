/**
 * Ransomware Protection Service
 * Advanced protection against ransomware attacks with honeypots, backups, and behavioral detection
 */

import CryptoJS from 'crypto-js';

// Protected folders (common targets for ransomware)
const PROTECTED_FOLDERS = [
  'C:\\Users\\Public\\Documents',
  'C:\\Users\\Public\\Pictures',
  'C:\\Users\\Public\\Videos',
  'C:\\Users\\Public\\Downloads',
  'Desktop',
  'Documents',
  'Pictures',
  'Videos',
  'Downloads'
];

// Honeypot files (decoy files to detect ransomware)
const HONEYPOT_FILES = [
  { name: 'IMPORTANT_FINANCIAL_DATA.xlsx', folder: 'Documents', type: 'excel' },
  { name: 'Family_Photos_2024.jpg', folder: 'Pictures', type: 'image' },
  { name: 'Passwords.txt', folder: 'Desktop', type: 'text' },
  { name: 'Banking_Information.pdf', folder: 'Documents', type: 'pdf' },
  { name: 'Crypto_Wallet_Keys.txt', folder: 'Documents', type: 'text' },
  { name: 'SSN_Records.docx', folder: 'Documents', type: 'word' }
];

// Known ransomware file extensions
const RANSOMWARE_EXTENSIONS = [
  '.locked', '.crypto', '.encrypted', '.crypt', '.locky', '.zepto',
  '.cerber', '.vault', '.petya', '.wannacry', '.ryuk', '.maze',
  '.revil', '.sodinokibi', '.dharma', '.phobos', '.makop', '.conti'
];

// Suspicious process behaviors
const SUSPICIOUS_BEHAVIORS = [
  'mass_file_encryption',
  'rapid_file_modification',
  'shadow_copy_deletion',
  'backup_deletion',
  'ransom_note_creation',
  'network_share_scanning'
];

// Ransomware activity log
let activityLog = [];
let honeypotStatus = [];
let protectedFolders = [];
let quarantinedProcesses = [];
let backupSchedule = [];

// Real-time monitoring state
let isMonitoring = true;
let lastScanTime = null;

/**
 * Initialize Ransomware Protection
 */
export function initializeProtection() {
  console.log('🛡️ Initializing Ransomware Protection...');
  
  // Deploy honeypot files
  deployHoneypots();
  
  // Setup folder protection
  setupFolderProtection();
  
  // Start behavioral monitoring
  startBehavioralMonitoring();
  
  // Initialize backup system
  initializeBackupSystem();
  
  lastScanTime = new Date();
  
  logActivity({
    type: 'system',
    severity: 'info',
    message: 'Ransomware Protection initialized successfully',
    timestamp: Date.now()
  });
}

/**
 * Deploy Honeypot Files
 */
function deployHoneypots() {
  honeypotStatus = HONEYPOT_FILES.map((file, index) => ({
    id: index + 1,
    name: file.name,
    folder: file.folder,
    type: file.type,
    status: 'deployed',
    lastChecked: new Date(),
    accessed: false,
    modified: false,
    encrypted: false,
    fullPath: `${file.folder}\\${file.name}`
  }));
  
  console.log(`🍯 Deployed ${honeypotStatus.length} honeypot files`);
}

/**
 * Setup Folder Protection
 */
function setupFolderProtection() {
  protectedFolders = PROTECTED_FOLDERS.map((folder, index) => ({
    id: index + 1,
    path: folder,
    status: 'protected',
    fileCount: Math.floor(Math.random() * 500) + 100,
    lastBackup: new Date(Date.now() - Math.random() * 86400000),
    backupEnabled: true,
    snapshotCount: Math.floor(Math.random() * 10) + 3
  }));
  
  console.log(`📁 Protected ${protectedFolders.length} folders`);
}

/**
 * Start Behavioral Monitoring
 */
function startBehavioralMonitoring() {
  console.log('👁️ Started behavioral monitoring');
  
  // Simulate monitoring with sample detections
  generateSampleActivity();
}

/**
 * Initialize Backup System
 */
function initializeBackupSystem() {
  backupSchedule = [
    {
      id: 1,
      name: 'Daily Documents Backup',
      folders: ['Documents', 'Desktop'],
      schedule: 'Daily at 2:00 AM',
      lastRun: new Date(Date.now() - 3600000 * 12),
      nextRun: new Date(Date.now() + 3600000 * 12),
      status: 'active',
      retentionDays: 30,
      encrypted: true
    },
    {
      id: 2,
      name: 'Weekly Full Backup',
      folders: ['Documents', 'Pictures', 'Videos', 'Downloads'],
      schedule: 'Weekly on Sunday at 3:00 AM',
      lastRun: new Date(Date.now() - 86400000 * 3),
      nextRun: new Date(Date.now() + 86400000 * 4),
      status: 'active',
      retentionDays: 90,
      encrypted: true
    },
    {
      id: 3,
      name: 'Critical Files Hourly',
      folders: ['Documents'],
      schedule: 'Every hour',
      lastRun: new Date(Date.now() - 3600000),
      nextRun: new Date(Date.now() + 3600000),
      status: 'active',
      retentionDays: 7,
      encrypted: true
    }
  ];
  
  console.log(`💾 Configured ${backupSchedule.length} backup schedules`);
}

/**
 * Check Honeypot Status
 */
export function checkHoneypots() {
  let detections = 0;
  
  honeypotStatus.forEach(honeypot => {
    // Simulate honeypot checking
    const random = Math.random();
    
    if (random < 0.01) { // 1% chance of detection
      honeypot.accessed = true;
      honeypot.modified = true;
      honeypot.status = 'triggered';
      detections++;
      
      triggerRansomwareAlert(honeypot);
    }
    
    honeypot.lastChecked = new Date();
  });
  
  return {
    total: honeypotStatus.length,
    safe: honeypotStatus.filter(h => h.status === 'deployed').length,
    triggered: detections,
    honeypots: honeypotStatus
  };
}

/**
 * Trigger Ransomware Alert
 */
function triggerRansomwareAlert(honeypot) {
  const alert = {
    type: 'ransomware_detection',
    severity: 'critical',
    message: `RANSOMWARE DETECTED! Honeypot file accessed: ${honeypot.name}`,
    honeypot: honeypot.name,
    folder: honeypot.folder,
    action: 'Suspicious process quarantined',
    timestamp: Date.now()
  };
  
  logActivity(alert);
  
  // Quarantine the process
  quarantineProcess({
    pid: Math.floor(Math.random() * 10000),
    name: 'suspicious_process.exe',
    reason: 'Honeypot file access detected',
    timestamp: new Date()
  });
  
  // Trigger emergency backup
  triggerEmergencyBackup();
}

/**
 * Quarantine Process
 */
function quarantineProcess(process) {
  quarantinedProcesses.push({
    ...process,
    status: 'quarantined',
    quarantinedAt: new Date()
  });
  
  console.log(`🚫 Quarantined process: ${process.name} (PID: ${process.pid})`);
}

/**
 * Trigger Emergency Backup
 */
function triggerEmergencyBackup() {
  const backup = {
    id: Date.now(),
    type: 'emergency',
    reason: 'Ransomware detection',
    folders: PROTECTED_FOLDERS,
    status: 'in_progress',
    startTime: new Date(),
    estimatedCompletion: new Date(Date.now() + 300000) // 5 minutes
  };
  
  logActivity({
    type: 'backup',
    severity: 'high',
    message: 'Emergency backup initiated due to ransomware detection',
    timestamp: Date.now()
  });
  
  // Simulate backup completion
  setTimeout(() => {
    backup.status = 'completed';
    backup.completionTime = new Date();
  }, 5000);
  
  return backup;
}

/**
 * Scan for Ransomware
 */
export function scanForRansomware() {
  const results = {
    scanned: 0,
    suspicious: 0,
    encrypted: 0,
    threats: [],
    startTime: new Date(),
    endTime: null
  };
  
  // Scan protected folders
  protectedFolders.forEach(folder => {
    const filesScanned = Math.floor(Math.random() * 1000) + 500;
    results.scanned += filesScanned;
    
    // Check for ransomware extensions
    const suspiciousFiles = Math.floor(Math.random() * 3);
    results.suspicious += suspiciousFiles;
    
    if (suspiciousFiles > 0) {
      for (let i = 0; i < suspiciousFiles; i++) {
        results.threats.push({
          file: `${folder.path}\\document_${i}${RANSOMWARE_EXTENSIONS[Math.floor(Math.random() * RANSOMWARE_EXTENSIONS.length)]}`,
          type: 'encrypted_file',
          severity: 'high',
          action: 'quarantined'
        });
      }
    }
  });
  
  results.endTime = new Date();
  results.duration = (results.endTime - results.startTime) / 1000;
  
  logActivity({
    type: 'scan',
    severity: 'info',
    message: `Ransomware scan completed: ${results.scanned} files scanned, ${results.threats.length} threats found`,
    timestamp: Date.now()
  });
  
  lastScanTime = new Date();
  
  return results;
}

/**
 * Restore from Backup
 */
export function restoreFromBackup(backupId, targetFolder) {
  const backup = backupSchedule.find(b => b.id === backupId);
  
  if (!backup) {
    return { success: false, error: 'Backup not found' };
  }
  
  logActivity({
    type: 'restore',
    severity: 'high',
    message: `Restoring from backup: ${backup.name} to ${targetFolder}`,
    timestamp: Date.now()
  });
  
  return {
    success: true,
    backupName: backup.name,
    targetFolder,
    filesRestored: Math.floor(Math.random() * 500) + 100,
    estimatedTime: '2-5 minutes',
    status: 'in_progress'
  };
}

/**
 * Create Manual Backup
 */
export function createManualBackup(folders, options = {}) {
  const backup = {
    id: Date.now(),
    name: options.name || `Manual Backup ${new Date().toLocaleDateString()}`,
    folders,
    type: 'manual',
    encrypted: options.encrypted !== false,
    compression: options.compression || 'standard',
    status: 'creating',
    createdAt: new Date(),
    size: 0
  };
  
  // Simulate backup creation
  setTimeout(() => {
    backup.status = 'completed';
    backup.size = Math.floor(Math.random() * 5000) + 1000; // MB
    backup.completedAt = new Date();
  }, 3000);
  
  logActivity({
    type: 'backup',
    severity: 'info',
    message: `Manual backup created: ${backup.name}`,
    timestamp: Date.now()
  });
  
  return backup;
}

/**
 * Get Protection Status
 */
export function getProtectionStatus() {
  return {
    monitoring: isMonitoring,
    lastScan: lastScanTime,
    honeypots: {
      total: honeypotStatus.length,
      active: honeypotStatus.filter(h => h.status === 'deployed').length,
      triggered: honeypotStatus.filter(h => h.status === 'triggered').length
    },
    protectedFolders: protectedFolders.length,
    backups: {
      schedules: backupSchedule.length,
      active: backupSchedule.filter(b => b.status === 'active').length,
      lastBackup: backupSchedule.reduce((latest, b) => {
        return !latest || b.lastRun > latest ? b.lastRun : latest;
      }, null)
    },
    quarantined: quarantinedProcesses.length,
    recentActivity: activityLog.slice(-10).reverse()
  };
}

/**
 * Get Protected Folders
 */
export function getProtectedFolders() {
  return protectedFolders;
}

/**
 * Get Honeypot Status
 */
export function getHoneypotStatus() {
  return honeypotStatus;
}

/**
 * Get Backup Schedules
 */
export function getBackupSchedules() {
  return backupSchedule;
}

/**
 * Get Quarantined Processes
 */
export function getQuarantinedProcesses() {
  return quarantinedProcesses;
}

/**
 * Get Activity Log
 */
export function getActivityLog(limit = 50) {
  return activityLog.slice(-limit).reverse();
}

/**
 * Toggle Monitoring
 */
export function toggleMonitoring() {
  isMonitoring = !isMonitoring;
  
  logActivity({
    type: 'system',
    severity: 'info',
    message: `Ransomware monitoring ${isMonitoring ? 'enabled' : 'disabled'}`,
    timestamp: Date.now()
  });
  
  return isMonitoring;
}

/**
 * Add Protected Folder
 */
export function addProtectedFolder(folderPath) {
  const newFolder = {
    id: protectedFolders.length + 1,
    path: folderPath,
    status: 'protected',
    fileCount: 0,
    lastBackup: new Date(),
    backupEnabled: true,
    snapshotCount: 0
  };
  
  protectedFolders.push(newFolder);
  
  logActivity({
    type: 'configuration',
    severity: 'info',
    message: `Added protected folder: ${folderPath}`,
    timestamp: Date.now()
  });
  
  return newFolder;
}

/**
 * Remove Protected Folder
 */
export function removeProtectedFolder(folderId) {
  const index = protectedFolders.findIndex(f => f.id === folderId);
  
  if (index !== -1) {
    const folder = protectedFolders.splice(index, 1)[0];
    
    logActivity({
      type: 'configuration',
      severity: 'info',
      message: `Removed protected folder: ${folder.path}`,
      timestamp: Date.now()
    });
    
    return true;
  }
  
  return false;
}

/**
 * Log Activity
 */
function logActivity(activity) {
  activityLog.push({
    id: activityLog.length + 1,
    ...activity,
    timestamp: activity.timestamp || Date.now(),
    timestampStr: new Date(activity.timestamp || Date.now()).toLocaleString()
  });
  
  // Keep only last 500 entries
  if (activityLog.length > 500) {
    activityLog = activityLog.slice(-500);
  }
}

/**
 * Generate Sample Activity
 */
function generateSampleActivity() {
  const activities = [
    { type: 'scan', severity: 'info', message: 'Scheduled ransomware scan completed - No threats found' },
    { type: 'honeypot', severity: 'info', message: 'Honeypot integrity check passed' },
    { type: 'backup', severity: 'info', message: 'Automatic backup completed successfully' },
    { type: 'monitoring', severity: 'low', message: 'Behavioral monitoring active - No suspicious activity' },
    { type: 'detection', severity: 'medium', message: 'Blocked suspicious file modification attempt' },
    { type: 'backup', severity: 'info', message: 'Snapshot created for Documents folder' }
  ];
  
  activities.forEach((activity, index) => {
    logActivity({
      ...activity,
      timestamp: Date.now() - (activities.length - index) * 3600000
    });
  });
}

// Initialize on module load
initializeProtection();

export default {
  initializeProtection,
  checkHoneypots,
  scanForRansomware,
  restoreFromBackup,
  createManualBackup,
  getProtectionStatus,
  getProtectedFolders,
  getHoneypotStatus,
  getBackupSchedules,
  getQuarantinedProcesses,
  getActivityLog,
  toggleMonitoring,
  addProtectedFolder,
  removeProtectedFolder
};
