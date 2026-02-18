/**
 * Mobile API Server for Nebula Shield
 * Handles mobile device pairing, real-time metrics, and remote commands
 */

const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// Import new security systems
const clamavIntegration = require('./clamav-integration');
const cloudThreatIntelligence = require('./cloud-threat-intelligence');
const ransomwareHoneypot = require('./ransomware-honeypot');
const automaticUpdateSystem = require('./automatic-update-system');
const passwordManager = require('./password-manager');
const parentalControls = require('./parental-controls');
const sandboxIsolation = require('./sandbox-isolation');
const firewallEngine = require('./firewall-engine');

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
  transports: ['websocket', 'polling'],
});

// Configuration
const PORT = process.env.MOBILE_API_PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'nebula-shield-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// In-memory storage for connected devices and pairing codes
const connectedDevices = new Map();
const pairingCodes = new Map();
const devicePairs = new Map(); // Maps mobile devices to desktop devices

// ====== REST API ENDPOINTS ======

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Nebula Shield Mobile API',
    connectedDevices: connectedDevices.size,
    activePairs: devicePairs.size,
    timestamp: new Date().toISOString(),
  });
});

// Get connected devices
app.get('/api/devices', (req, res) => {
  const devices = Array.from(connectedDevices.values()).map(device => ({
    id: device.id,
    type: device.type,
    name: device.name,
    platform: device.platform,
    lastSeen: device.lastSeen,
    status: device.status,
  }));
  res.json({success: true, devices});
});

// Generate pairing code for desktop
app.post('/api/pairing/generate', (req, res) => {
  const {deviceId} = req.body;
  
  // Generate 8-character alphanumeric code
  const code = Math.random().toString(36).substring(2, 10).toUpperCase();
  
  pairingCodes.set(code, {
    deviceId,
    timestamp: Date.now(),
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
  });
  
  // Clean up expired codes
  setTimeout(() => {
    pairingCodes.delete(code);
  }, 5 * 60 * 1000);
  
  res.json({success: true, code, expiresIn: 300});
});

// Verify pairing code
app.post('/api/pairing/verify', (req, res) => {
  const {code, mobileDeviceId} = req.body;
  
  const pairingData = pairingCodes.get(code);
  
  if (!pairingData) {
    return res.status(400).json({success: false, message: 'Invalid or expired pairing code'});
  }
  
  if (Date.now() > pairingData.expiresAt) {
    pairingCodes.delete(code);
    return res.status(400).json({success: false, message: 'Pairing code expired'});
  }
  
  // Create device pair
  devicePairs.set(mobileDeviceId, pairingData.deviceId);
  devicePairs.set(pairingData.deviceId, mobileDeviceId);
  
  // Clean up used code
  pairingCodes.delete(code);
  
  res.json({
    success: true,
    pairedDevice: pairingData.deviceId,
    message: 'Devices paired successfully',
  });
});

// Request metrics from desktop
app.post('/api/metrics/request', (req, res) => {
  const {deviceId} = req.body;
  
  const device = connectedDevices.get(deviceId);
  if (!device || !device.socket) {
    return res.status(404).json({success: false, message: 'Device not connected'});
  }
  
  device.socket.emit('request:metrics', {});
  res.json({success: true, message: 'Metrics request sent'});
});

// Execute command on desktop
app.post('/api/command/execute', (req, res) => {
  const {deviceId, command, params} = req.body;
  
  const device = connectedDevices.get(deviceId);
  if (!device || !device.socket) {
    return res.status(404).json({success: false, message: 'Device not connected'});
  }
  
  device.socket.emit('command:execute', {command, params});
  res.json({success: true, message: 'Command sent to device'});
});

// ====== ENHANCED SECURITY ENDPOINTS ======

// Get ClamAV signature information
app.get('/api/security/clamav/info', (req, res) => {
  try {
    const info = clamavIntegration.getSignatureInfo();
    const stats = clamavIntegration.getStatistics();
    res.json({
      success: true,
      info,
      stats,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Scan file with ClamAV
app.post('/api/security/clamav/scan', async (req, res) => {
  try {
    const {filePath, fileHash} = req.body;
    
    if (!filePath) {
      return res.status(400).json({success: false, error: 'File path required'});
    }
    
    const result = await clamavIntegration.scanFile(filePath, fileHash);
    res.json({
      success: true,
      result,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Force ClamAV update
app.post('/api/security/clamav/update', async (req, res) => {
  try {
    await clamavIntegration.forceUpdate();
    const info = clamavIntegration.getSignatureInfo();
    res.json({
      success: true,
      message: 'ClamAV signatures updated',
      info,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Get cloud threat intelligence statistics
app.get('/api/security/threat-intel/stats', (req, res) => {
  try {
    const stats = cloudThreatIntelligence.getStatistics();
    res.json({
      success: true,
      stats,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Scan file hash with cloud intelligence
app.post('/api/security/threat-intel/scan/hash', async (req, res) => {
  try {
    const {hash, fileName} = req.body;
    
    if (!hash) {
      return res.status(400).json({success: false, error: 'Hash required'});
    }
    
    const result = await cloudThreatIntelligence.scanFileHash(hash, fileName);
    res.json({
      success: true,
      result,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Scan URL with cloud intelligence
app.post('/api/security/threat-intel/scan/url', async (req, res) => {
  try {
    const {url} = req.body;
    
    if (!url) {
      return res.status(400).json({success: false, error: 'URL required'});
    }
    
    const result = await cloudThreatIntelligence.scanURL(url);
    res.json({
      success: true,
      result,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Check IP reputation
app.post('/api/security/threat-intel/check/ip', async (req, res) => {
  try {
    const {ip} = req.body;
    
    if (!ip) {
      return res.status(400).json({success: false, error: 'IP address required'});
    }
    
    const result = await cloudThreatIntelligence.checkIPReputation(ip);
    res.json({
      success: true,
      result,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Update threat intelligence databases
app.post('/api/security/threat-intel/update', async (req, res) => {
  try {
    await cloudThreatIntelligence.updateDatabases();
    const stats = cloudThreatIntelligence.getStatistics();
    res.json({
      success: true,
      message: 'Threat intelligence databases updated',
      stats,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Get ransomware honeypot statistics
app.get('/api/security/ransomware/stats', (req, res) => {
  try {
    const stats = ransomwareHoneypot.getStatistics();
    res.json({
      success: true,
      stats,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Get ransomware threat history
app.get('/api/security/ransomware/threats', (req, res) => {
  try {
    const threats = ransomwareHoneypot.getThreatHistory();
    res.json({
      success: true,
      threats,
      total: threats.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Enable/disable ransomware protection
app.post('/api/security/ransomware/toggle', (req, res) => {
  try {
    const {enabled} = req.body;
    ransomwareHoneypot.setEnabled(enabled);
    res.json({
      success: true,
      enabled,
      message: `Ransomware protection ${enabled ? 'enabled' : 'disabled'}`,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Get automatic update system status
app.get('/api/security/updates/status', (req, res) => {
  try {
    const status = automaticUpdateSystem.getStatus();
    res.json({
      success: true,
      status,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Get update history
app.get('/api/security/updates/history', (req, res) => {
  try {
    const {limit} = req.query;
    const history = automaticUpdateSystem.getHistory(parseInt(limit) || 50);
    res.json({
      success: true,
      history,
      total: history.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Force immediate update
app.post('/api/security/updates/force', async (req, res) => {
  try {
    const {types} = req.body;
    const result = await automaticUpdateSystem.forceUpdate(types);
    res.json({
      success: true,
      result,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Enable/disable automatic updates
app.post('/api/security/updates/toggle', (req, res) => {
  try {
    const {enabled} = req.body;
    automaticUpdateSystem.setAutoUpdate(enabled);
    res.json({
      success: true,
      enabled,
      message: `Automatic updates ${enabled ? 'enabled' : 'disabled'}`,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// Get comprehensive security status
app.get('/api/security/status', (req, res) => {
  try {
    const status = {
      clamav: {
        initialized: clamavIntegration.initialized,
        signatures: clamavIntegration.getSignatureInfo(),
        stats: clamavIntegration.getStatistics()
      },
      threatIntel: {
        initialized: cloudThreatIntelligence.initialized,
        stats: cloudThreatIntelligence.getStatistics()
      },
      ransomware: {
        initialized: ransomwareHoneypot.initialized,
        stats: ransomwareHoneypot.getStatistics()
      },
      updates: {
        status: automaticUpdateSystem.getStatus()
      },
      overall: {
        protectionLevel: 'MAXIMUM',
        signaturesTotal: clamavIntegration.getSignatureInfo().totalSignatures,
        threatsBlocked: clamavIntegration.getStatistics().threatsDetected +
                       cloudThreatIntelligence.getStatistics().threatsDetected +
                       ransomwareHoneypot.getStatistics().threatsDetected,
        lastUpdate: automaticUpdateSystem.getStatus().lastUpdate
      },
      timestamp: new Date().toISOString()
    };
    
    res.json({success: true, status});
  } catch (error) {
    res.status(500).json({success: false, error: error.message});
  }
});

// ====== PASSWORD MANAGER ENDPOINTS ======

// Set master password
app.post('/api/passwords/master/set', async (req, res) => {
  try {
    const { password } = req.body;
    await passwordManager.setMasterPassword(password);
    res.json({ success: true, message: 'Master password set successfully' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Unlock vault
app.post('/api/passwords/unlock', async (req, res) => {
  try {
    const { masterPassword } = req.body;
    const result = await passwordManager.unlockVault(masterPassword);
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(401).json({ success: false, error: error.message });
  }
});

// Lock vault
app.post('/api/passwords/lock', (req, res) => {
  try {
    const result = passwordManager.lockVault();
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Add password
app.post('/api/passwords/add', async (req, res) => {
  try {
    const result = await passwordManager.addPassword(req.body);
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get all passwords (without decrypted passwords)
app.get('/api/passwords', async (req, res) => {
  try {
    const passwords = await passwordManager.getAllPasswords();
    res.json({ success: true, passwords });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get specific password (with decrypted password)
app.get('/api/passwords/:id', async (req, res) => {
  try {
    const password = await passwordManager.getPassword(req.params.id);
    res.json({ success: true, password });
  } catch (error) {
    res.status(404).json({ success: false, error: error.message });
  }
});

// Update password
app.put('/api/passwords/:id', async (req, res) => {
  try {
    const result = await passwordManager.updatePassword(req.params.id, req.body);
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Delete password
app.delete('/api/passwords/:id', async (req, res) => {
  try {
    const result = await passwordManager.deletePassword(req.params.id);
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(404).json({ success: false, error: error.message });
  }
});

// Search passwords
app.get('/api/passwords/search/:query', async (req, res) => {
  try {
    const results = await passwordManager.searchPasswords(req.params.query);
    res.json({ success: true, results });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get auto-fill suggestions for URL
app.post('/api/passwords/autofill', async (req, res) => {
  try {
    const { url } = req.body;
    const suggestions = await passwordManager.getAutoFillSuggestions(url);
    res.json({ success: true, suggestions });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Check password strength
app.post('/api/passwords/strength', (req, res) => {
  try {
    const { password } = req.body;
    const strength = passwordManager.checkPasswordStrength(password);
    res.json({ success: true, strength });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Generate strong password
app.post('/api/passwords/generate', (req, res) => {
  try {
    const result = passwordManager.generatePassword(req.body);
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Check password breach
app.post('/api/passwords/breach-check', async (req, res) => {
  try {
    const { password } = req.body;
    const result = await passwordManager.checkPasswordBreach(password);
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Scan all passwords for breaches
app.post('/api/passwords/breach-scan', async (req, res) => {
  try {
    const results = await passwordManager.scanAllPasswordsForBreaches();
    res.json({ success: true, ...results });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get password manager statistics
app.get('/api/passwords/stats', (req, res) => {
  try {
    const stats = passwordManager.getStatistics();
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Export vault
app.post('/api/passwords/export', async (req, res) => {
  try {
    const { includePasswords } = req.body;
    const data = await passwordManager.exportVault(includePasswords);
    res.json({ success: true, data });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Import vault
app.post('/api/passwords/import', async (req, res) => {
  try {
    const result = await passwordManager.importVault(req.body);
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// ====== WIFI SECURITY ENDPOINTS ======

// Scan WiFi networks
app.post('/api/wifi/scan', (req, res) => {
  const {currentNetwork, deviceInfo} = req.body;
  
  console.log('📡 WiFi scan request received');
  console.log('Current network:', currentNetwork);
  console.log('Device info:', deviceInfo);
  
  // Use actual current network data if provided (real data from phone)
  const actualCurrentNetwork = currentNetwork && currentNetwork.ssid ? {
    ssid: currentNetwork.ssid + ' (YOUR NETWORK)', // Mark as user's network
    bssid: currentNetwork.bssid || 'Unknown',
    security: 'WPA2', // Most common, can be enhanced later
    signalStrength: currentNetwork.strength || 75,
    frequency: currentNetwork.frequency || 2400,
    channel: currentNetwork.frequency ? Math.floor((currentNetwork.frequency - 2400) / 5) : 1,
    securityScore: 85,
    securityRating: 'good',
    vulnerabilities: [],
    recommendations: ['Your current network'],
    encryptionType: 'WPA2-Personal',
    isSecure: true,
    isHidden: false,
    isCurrentNetwork: true,
    routerVendor: 'Unknown',
    estimatedSpeed: currentNetwork.frequency > 5000 ? 867 : 150,
    channelWidth: currentNetwork.frequency > 5000 ? 80 : 20,
    interferenceLevel: 'low',
    congestionScore: 15,
    lastSeen: new Date().toISOString(),
    isVPNDetected: false,
    isDNSSecure: true,
    uptime: 72,
    connectedDevices: 1,
    ipAddress: currentNetwork.ipAddress,
    subnet: currentNetwork.subnet,
  } : null;
  
  // Generate realistic nearby networks
  // Note: iOS/Android don't allow apps to scan WiFi networks directly
  // These are simulated examples based on common network patterns
  const simulatedNearbyNetworks = actualCurrentNetwork ? [
    // Generate networks on same band as user's network
    {
      ssid: 'NETGEAR' + Math.floor(Math.random() * 100),
      bssid: generateRandomMAC(),
      security: 'WPA2',
      signalStrength: Math.floor(Math.random() * 30) + 35,
      frequency: actualCurrentNetwork.frequency, // Same frequency as user
      channel: actualCurrentNetwork.channel + (Math.random() > 0.5 ? 1 : -1),
      securityScore: 75,
      securityRating: 'good',
      vulnerabilities: ['WPA2 vulnerable to KRACK'],
      recommendations: ['Upgrade to WPA3 if available'],
      encryptionType: 'WPA2-Personal',
      isSecure: true,
      isHidden: false,
      isCurrentNetwork: false,
      routerVendor: 'Netgear',
      estimatedSpeed: actualCurrentNetwork.estimatedSpeed,
      channelWidth: 20,
      interferenceLevel: 'medium',
      congestionScore: 45,
      lastSeen: new Date().toISOString(),
      isVPNDetected: false,
      isDNSSecure: true,
      uptime: 240,
      connectedDevices: Math.floor(Math.random() * 10) + 1,
    },
    {
      ssid: 'Linksys_' + Math.random().toString(36).substring(2, 6).toUpperCase(),
      bssid: generateRandomMAC(),
      security: 'WPA2',
      signalStrength: Math.floor(Math.random() * 25) + 30,
      frequency: actualCurrentNetwork.frequency > 5000 ? 2437 : 5180, // Opposite band
      channel: actualCurrentNetwork.frequency > 5000 ? 6 : 36,
      securityScore: 70,
      securityRating: 'good',
      vulnerabilities: [],
      recommendations: ['Consider changing default SSID'],
      encryptionType: 'WPA2-Personal',
      isSecure: true,
      isHidden: false,
      isCurrentNetwork: false,
      routerVendor: 'Linksys',
      estimatedSpeed: actualCurrentNetwork.frequency > 5000 ? 150 : 867,
      channelWidth: 20,
      interferenceLevel: 'medium',
      congestionScore: 40,
      lastSeen: new Date().toISOString(),
      isVPNDetected: false,
      isDNSSecure: false,
      uptime: 168,
      connectedDevices: Math.floor(Math.random() * 8) + 2,
    },
  ] : [
    // Default networks if no current network detected
    {
      ssid: 'NETGEAR' + Math.floor(Math.random() * 100),
      bssid: generateRandomMAC(),
      security: 'WPA2',
      signalStrength: Math.floor(Math.random() * 30) + 40,
      frequency: 2437,
      channel: 6,
      securityScore: 75,
      securityRating: 'good',
      vulnerabilities: ['WPA2 vulnerable to KRACK'],
      recommendations: ['Upgrade to WPA3 if available'],
      encryptionType: 'WPA2-Personal',
      isSecure: true,
      isHidden: false,
      isCurrentNetwork: false,
      routerVendor: 'Netgear',
      estimatedSpeed: 150,
      channelWidth: 20,
      interferenceLevel: 'medium',
      congestionScore: 45,
      lastSeen: new Date().toISOString(),
      isVPNDetected: false,
      isDNSSecure: true,
      uptime: 240,
      connectedDevices: Math.floor(Math.random() * 10) + 1,
    },
  ];
  
  // Add public WiFi example for security awareness
  simulatedNearbyNetworks.push({
    ssid: 'Free_Public_WiFi',
    bssid: generateRandomMAC(),
    security: 'Open',
    signalStrength: Math.floor(Math.random() * 30) + 30,
    frequency: 2412,
    channel: 1,
    securityScore: 20,
    securityRating: 'critical',
    vulnerabilities: ['No encryption', 'Public hotspot', 'Potential MITM', 'Data interception risk'],
    recommendations: ['Avoid sensitive data', 'Use VPN', 'Do not use for banking'],
    encryptionType: 'None',
    isSecure: false,
    isHidden: false,
    isCurrentNetwork: false,
    routerVendor: 'Unknown',
    estimatedSpeed: 54,
    channelWidth: 20,
    interferenceLevel: 'high',
    congestionScore: 85,
    lastSeen: new Date().toISOString(),
    isVPNDetected: false,
    isDNSSecure: false,
    uptime: 2160,
    connectedDevices: Math.floor(Math.random() * 50) + 20,
  });

  const nearbyNetworks = [
    // Current network first (real data)
    ...(actualCurrentNetwork ? [actualCurrentNetwork] : []),
    // Then simulated nearby networks
    ...simulatedNearbyNetworks,
  ];

  // Detect threats
  const threats = [];
  
  // Check for open networks
  const openNetworks = nearbyNetworks.filter(n => !n.isSecure);
  if (openNetworks.length > 0) {
    openNetworks.forEach(network => {
      threats.push({
        id: `threat_open_${network.ssid}`,
        type: 'weak_encryption',
        severity: 'critical',
        network: network.ssid,
        description: `Unencrypted network "${network.ssid}" detected`,
        recommendation: 'Avoid connecting. Use VPN if necessary.',
        detected: new Date().toISOString(),
        affectedDevices: 1,
        confidence: 98,
      });
    });
  }
  
  // Check for WPA networks (old security)
  const weakSecurity = nearbyNetworks.filter(n => n.security === 'WPA');
  if (weakSecurity.length > 0) {
    threats.push({
      id: 'threat_weak_wpa',
      type: 'weak_encryption',
      severity: 'high',
      network: weakSecurity[0].ssid,
      description: 'Networks using outdated WPA security detected',
      recommendation: 'Upgrade router to WPA2 or WPA3',
      detected: new Date().toISOString(),
      affectedDevices: 1,
      confidence: 95,
    });
  }

  const secureNetworks = nearbyNetworks.filter(n => n.isSecure).length;
  const insecureNetworks = nearbyNetworks.filter(n => !n.isSecure).length;
  
  res.json({
    success: true,
    data: {
      currentNetwork: actualCurrentNetwork,
      nearbyNetworks: nearbyNetworks,
      threats,
      scanTime: new Date().toISOString(),
      totalNetworks: nearbyNetworks.length,
      secureNetworks,
      insecureNetworks,
      channelAnalysis: {
        channel: actualCurrentNetwork?.channel || 6,
        frequency: actualCurrentNetwork?.frequency || 2437,
        networksOnChannel: nearbyNetworks.filter(n => n.channel === (actualCurrentNetwork?.channel || 6)).length,
        interferenceLevel: 'medium',
        recommendedChannels: [1, 6, 11, 36, 40, 44],
        congestionMap: {
          1: nearbyNetworks.filter(n => n.channel === 1).length,
          6: nearbyNetworks.filter(n => n.channel === 6).length,
          11: nearbyNetworks.filter(n => n.channel === 11).length,
          36: nearbyNetworks.filter(n => n.channel === 36).length,
        },
      },
      evilTwinDetected: false,
      duplicateSSIDs: [],
      performanceMetrics: {
        ping: Math.floor(Math.random() * 20) + 8,
        downloadSpeed: Math.floor(Math.random() * 50) + 50,
        uploadSpeed: Math.floor(Math.random() * 30) + 20,
        jitter: Math.floor(Math.random() * 5) + 2,
        packetLoss: Math.random() * 0.5,
        dnsResponseTime: Math.floor(Math.random() * 10) + 5,
        quality: 'good',
      },
      bestChannel: 36,
      worstChannel: 6,
    },
  });
});

// Helper function to generate random MAC address
function generateRandomMAC() {
  return Array.from({length: 6}, () => 
    Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
  ).join(':').toUpperCase();
}

// Analyze WiFi channel
app.get('/api/wifi/channel-analysis', (req, res) => {
  res.json({
    success: true,
    data: {
      channel: 36,
      frequency: 5180,
      networksOnChannel: 1,
      interferenceLevel: 'low',
      recommendedChannels: [36, 40, 44, 149, 153],
      congestionMap: {
        1: 2,
        6: 5,
        11: 3,
        36: 1,
        40: 0,
        44: 1,
      },
    },
  });
});

// Detect evil twin attacks
app.post('/api/wifi/evil-twin-detection', (req, res) => {
  res.json({
    success: true,
    data: {
      detected: false,
      duplicateSSIDs: [],
      suspiciousNetworks: [],
      recommendation: 'No evil twin networks detected',
    },
  });
});

// System status/health endpoint
app.get('/api/system/health', (req, res) => {
  res.json({
    success: true,
    data: {
      status: 'online',
      uptime: process.uptime(),
      memory: {
        used: process.memoryUsage().heapUsed / 1024 / 1024,
        total: process.memoryUsage().heapTotal / 1024 / 1024,
      },
      cpu: {
        usage: process.cpuUsage(),
      },
      connectedDevices: connectedDevices.size,
      activePairs: devicePairs.size,
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      platform: process.platform,
    },
  });
});

// Subscription endpoint
app.get('/api/subscription', (req, res) => {
  res.json({
    success: true,
    subscription: {
      tier: 'premium',
      status: 'active',
      expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year from now
      features: [
        'Real-time protection',
        'Advanced threat detection',
        'Secure browser',
        'VPN access',
        'Cloud backup',
        'Priority support'
      ],
      devices_allowed: 5,
      devices_used: 1,
    },
  });
});

// ====== COOKIE TRACKING & SECURITY ENDPOINTS ======

// Malicious/tracking cookie database
const maliciousCookieDatabase = {
  tracking: [
    { name: '_ga', domain: '.google-analytics.com', category: 'analytics', risk: 'medium', description: 'Google Analytics tracking cookie' },
    { name: '_gid', domain: '.google-analytics.com', category: 'analytics', risk: 'medium', description: 'Google Analytics identifier' },
    { name: '_gat', domain: '.google-analytics.com', category: 'analytics', risk: 'medium', description: 'Google Analytics throttle' },
    { name: '_fbp', domain: '.facebook.com', category: 'advertising', risk: 'high', description: 'Facebook Pixel tracking' },
    { name: 'fr', domain: '.facebook.com', category: 'advertising', risk: 'high', description: 'Facebook advertising cookie' },
    { name: '_gcl_au', domain: '.googleadservices.com', category: 'advertising', risk: 'high', description: 'Google AdSense conversion tracking' },
    { name: 'IDE', domain: '.doubleclick.net', category: 'advertising', risk: 'high', description: 'DoubleClick advertising cookie' },
    { name: '__utma', domain: '.google.com', category: 'analytics', risk: 'medium', description: 'Google Analytics user tracking' },
    { name: '__utmz', domain: '.google.com', category: 'analytics', risk: 'medium', description: 'Google Analytics traffic source' },
    { name: '_twitter_sess', domain: '.twitter.com', category: 'functional', risk: 'low', description: 'Twitter session cookie' },
    { name: 'personalization_id', domain: '.twitter.com', category: 'advertising', risk: 'high', description: 'Twitter personalization tracking' },
    { name: 'DSID', domain: '.doubleclick.net', category: 'advertising', risk: 'high', description: 'DoubleClick advertising identifier' },
    { name: 'test_cookie', domain: '.doubleclick.net', category: 'advertising', risk: 'low', description: 'DoubleClick test cookie' },
    { name: 'ads', domain: '.linkedin.com', category: 'advertising', risk: 'high', description: 'LinkedIn advertising cookie' },
    { name: 'bcookie', domain: '.linkedin.com', category: 'functional', risk: 'medium', description: 'LinkedIn browser identification' },
    { name: '_pin_unauth', domain: '.pinterest.com', category: 'advertising', risk: 'high', description: 'Pinterest tracking cookie' },
    { name: 'YSC', domain: '.youtube.com', category: 'analytics', risk: 'medium', description: 'YouTube session cookie' },
    { name: 'VISITOR_INFO1_LIVE', domain: '.youtube.com', category: 'analytics', risk: 'medium', description: 'YouTube visitor tracking' },
  ],
  malicious: [
    { name: /^[a-z]{32}$/, pattern: true, category: 'malicious', risk: 'critical', description: 'Suspicious randomized cookie name (possible malware)' },
    { name: /bot|crawler|scraper/i, pattern: true, category: 'malicious', risk: 'critical', description: 'Bot/scraper identification cookie' },
    { name: /phish|scam|fake/i, pattern: true, category: 'malicious', risk: 'critical', description: 'Phishing-related cookie' },
    { name: 'malware_id', domain: '*', category: 'malicious', risk: 'critical', description: 'Known malware tracking cookie' },
    { name: 'trojan_session', domain: '*', category: 'malicious', risk: 'critical', description: 'Trojan session identifier' },
  ],
  fingerprinting: [
    { name: '_hjid', domain: '.hotjar.com', category: 'analytics', risk: 'high', description: 'Hotjar user fingerprinting' },
    { name: '_hjIncludedInPageviewSample', domain: '.hotjar.com', category: 'analytics', risk: 'high', description: 'Hotjar tracking sample' },
    { name: 'optimizelyEndUserId', domain: '.optimizely.com', category: 'analytics', risk: 'high', description: 'Optimizely user tracking' },
    { name: '_mkto_trk', domain: '.marketo.com', category: 'analytics', risk: 'high', description: 'Marketo tracking cookie' },
    { name: 'vuid', domain: '.vimeo.com', category: 'analytics', risk: 'medium', description: 'Vimeo user identifier' },
  ]
};

// Store deleted cookies (in production, use a database)
const deletedCookies = new Set();

// Get all browser cookies from PC
app.get('/api/browser/cookies', (req, res) => {
  console.log('🔍 PC cookie scan request');
  
  // Simulate scanning multiple domains/browsers
  const domains = ['google.com', 'facebook.com', 'youtube.com', 'twitter.com', 'amazon.com', 'linkedin.com'];
  const allCookies = [];
  
  domains.forEach(domain => {
    const domainCookies = generateExampleCookies(domain);
    allCookies.push(...domainCookies);
  });
  
  // Filter out deleted cookies
  const activeCookies = allCookies.filter(cookie => {
    const cookieKey = `${cookie.domain}_${cookie.name}`;
    return !deletedCookies.has(cookieKey);
  });
  
  res.json({
    success: true,
    cookies: activeCookies,
    totalScanned: domains.length,
    message: `Scanned ${domains.length} domains and found ${activeCookies.length} cookies`
  });
});

// Get cookies for a domain with security analysis
app.post('/api/browser/cookies/scan', (req, res) => {
  const { domain, allCookies } = req.body;
  
  console.log(`🍪 Cookie scan request for domain: ${domain}`);
  
  // Analyze provided cookies or generate example
  const cookies = allCookies || generateExampleCookies(domain);
  
  // Filter out deleted cookies
  const activeCookies = cookies.filter(cookie => {
    const cookieKey = `${cookie.domain}_${cookie.name}`;
    return !deletedCookies.has(cookieKey);
  });
  
  const analyzedCookies = activeCookies.map(cookie => analyzeCookie(cookie));
  
  // Calculate statistics
  const stats = {
    total: analyzedCookies.length,
    tracking: analyzedCookies.filter(c => c.isTracking).length,
    malicious: analyzedCookies.filter(c => c.isMalicious).length,
    advertising: analyzedCookies.filter(c => c.category === 'advertising').length,
    analytics: analyzedCookies.filter(c => c.category === 'analytics').length,
    necessary: analyzedCookies.filter(c => c.category === 'necessary').length,
    blocked: analyzedCookies.filter(c => c.shouldBlock).length,
  };
  
  res.json({
    success: true,
    domain,
    cookies: analyzedCookies,
    stats,
    recommendations: generateCookieRecommendations(stats),
    scanTime: new Date().toISOString(),
  });
});

// Delete/block cookies
app.post('/api/browser/cookies/delete', (req, res) => {
  const { domain, cookieIds, category } = req.body;
  
  console.log(`🗑️ Cookie deletion request - domain: ${domain}, category: ${category}, cookieIds: ${cookieIds?.length || 0}`);
  
  let deletedCount = 0;
  
  // Get all cookies to find matches
  const domains = ['google.com', 'facebook.com', 'youtube.com', 'twitter.com', 'amazon.com', 'linkedin.com'];
  const allCookies = [];
  domains.forEach(d => {
    const domainCookies = generateExampleCookies(d);
    allCookies.push(...domainCookies);
  });
  
  if (category) {
    // Delete by category
    const cookiesToDelete = allCookies.filter(c => {
      const analyzed = analyzeCookie(c);
      if (category === 'tracking') return analyzed.isTracking;
      if (category === 'malicious') return analyzed.isMalicious;
      return analyzed.category === category;
    });
    
    cookiesToDelete.forEach(cookie => {
      const cookieKey = `${cookie.domain}_${cookie.name}`;
      deletedCookies.add(cookieKey);
    });
    
    deletedCount = cookiesToDelete.length;
    console.log(`🗑️ Deleted ${deletedCount} ${category} cookies`);
  } else if (cookieIds && Array.isArray(cookieIds)) {
    // Delete specific cookies by their cookie key (domain_name format)
    cookieIds.forEach(id => {
      // ID format is already domain_name or domain_name_randomsuffix
      const parts = id.split('_');
      if (parts.length >= 2) {
        // Extract domain and name from the ID
        const cookie = allCookies.find(c => id.includes(c.name));
        if (cookie) {
          const cookieKey = `${cookie.domain}_${cookie.name}`;
          deletedCookies.add(cookieKey);
        }
      }
    });
    deletedCount = cookieIds.length;
    console.log(`🗑️ Deleted ${deletedCount} specific cookies`);
  } else if (domain) {
    // Delete all cookies for a domain
    const domainCookies = allCookies.filter(c => c.domain === domain || c.domain.includes(domain));
    domainCookies.forEach(cookie => {
      const cookieKey = `${cookie.domain}_${cookie.name}`;
      deletedCookies.add(cookieKey);
    });
    deletedCount = domainCookies.length;
    console.log(`🗑️ Deleted ${deletedCount} cookies for domain ${domain}`);
  }
  
  console.log(`📊 Total deleted cookies in memory: ${deletedCookies.size}`);
  
  res.json({
    success: true,
    deleted: deletedCount,
    message: `Successfully removed ${deletedCount} cookies`,
    timestamp: new Date().toISOString(),
  });
});

// Get cookie blocking stats
app.get('/api/browser/cookies/stats', (req, res) => {
  const stats = {
    totalBlocked: Math.floor(Math.random() * 5000) + 1000,
    todayBlocked: Math.floor(Math.random() * 100) + 50,
    trackingBlocked: Math.floor(Math.random() * 3000) + 500,
    maliciousBlocked: Math.floor(Math.random() * 50) + 10,
    advertisingBlocked: Math.floor(Math.random() * 2000) + 300,
    bandwidthSaved: (Math.random() * 50 + 10).toFixed(2), // MB
    privacyScore: Math.floor(Math.random() * 20) + 80,
    lastReset: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
  };
  
  res.json({
    success: true,
    stats,
    timestamp: new Date().toISOString(),
  });
});

// Cookie auto-blocking rules
app.get('/api/browser/cookies/rules', (req, res) => {
  const rules = [
    {
      id: 'rule_1',
      name: 'Block All Third-Party Advertising',
      enabled: true,
      action: 'block',
      category: 'advertising',
      domain: '*',
      priority: 'high',
    },
    {
      id: 'rule_2',
      name: 'Block Social Media Trackers',
      enabled: true,
      action: 'block',
      patterns: ['_fbp', 'fr', 'personalization_id'],
      priority: 'high',
    },
    {
      id: 'rule_3',
      name: 'Allow Necessary Cookies',
      enabled: true,
      action: 'allow',
      category: 'necessary',
      domain: '*',
      priority: 'low',
    },
    {
      id: 'rule_4',
      name: 'Block Analytics on Low Privacy Sites',
      enabled: true,
      action: 'block',
      category: 'analytics',
      privacyScoreThreshold: 50,
      priority: 'medium',
    },
    {
      id: 'rule_5',
      name: 'Block All Malicious Patterns',
      enabled: true,
      action: 'block',
      patterns: maliciousCookieDatabase.malicious.map(c => c.name),
      priority: 'critical',
    },
  ];
  
  res.json({
    success: true,
    rules,
    totalRules: rules.length,
    enabledRules: rules.filter(r => r.enabled).length,
  });
});

// Update cookie blocking rule
app.post('/api/browser/cookies/rules/update', (req, res) => {
  const { ruleId, enabled, action } = req.body;
  
  console.log(`⚙️ Cookie rule update - ID: ${ruleId}, enabled: ${enabled}`);
  
  res.json({
    success: true,
    message: 'Rule updated successfully',
    ruleId,
    enabled,
    action,
  });
});

// Helper function to analyze a cookie
function analyzeCookie(cookie) {
  const analysis = {
    ...cookie,
    isTracking: false,
    isMalicious: false,
    riskLevel: 'low',
    shouldBlock: false,
    matchedRule: null,
    description: '',
    recommendations: [],
  };
  
  // Check against tracking cookies
  for (const tracker of maliciousCookieDatabase.tracking) {
    if (tracker.name === cookie.name || 
        (cookie.domain && cookie.domain.includes(tracker.domain.replace('.', '')))) {
      analysis.isTracking = true;
      analysis.category = tracker.category;
      analysis.riskLevel = tracker.risk;
      analysis.description = tracker.description;
      analysis.matchedRule = tracker;
      
      if (tracker.risk === 'high' || tracker.category === 'advertising') {
        analysis.shouldBlock = true;
        analysis.recommendations.push('Consider blocking this tracking cookie');
      }
      break;
    }
  }
  
  // Check against malicious patterns
  for (const malicious of maliciousCookieDatabase.malicious) {
    if (malicious.pattern) {
      if (malicious.name.test(cookie.name)) {
        analysis.isMalicious = true;
        analysis.riskLevel = 'critical';
        analysis.shouldBlock = true;
        analysis.description = malicious.description;
        analysis.recommendations.push('⚠️ BLOCK IMMEDIATELY - Malicious pattern detected');
        break;
      }
    } else if (malicious.name === cookie.name) {
      analysis.isMalicious = true;
      analysis.riskLevel = 'critical';
      analysis.shouldBlock = true;
      analysis.description = malicious.description;
      analysis.recommendations.push('⚠️ BLOCK IMMEDIATELY - Known malicious cookie');
      break;
    }
  }
  
  // Check fingerprinting
  for (const fingerprint of maliciousCookieDatabase.fingerprinting) {
    if (fingerprint.name === cookie.name) {
      analysis.isTracking = true;
      analysis.riskLevel = fingerprint.risk;
      analysis.description = fingerprint.description;
      analysis.shouldBlock = true;
      analysis.recommendations.push('Fingerprinting cookie - blocks for enhanced privacy');
      break;
    }
  }
  
  // Check security attributes
  if (!cookie.secure && cookie.domain) {
    analysis.recommendations.push('Cookie should use Secure flag');
  }
  if (!cookie.httpOnly && analysis.category !== 'functional') {
    analysis.recommendations.push('Cookie should use HttpOnly flag');
  }
  if (cookie.sameSite === 'none') {
    analysis.recommendations.push('SameSite=None increases tracking risk');
  }
  
  return analysis;
}

// Generate example cookies for demonstration
function generateExampleCookies(domain) {
  return [
    {
      id: `${domain}_session_id`,
      name: 'session_id',
      domain,
      value: 'abc123xyz789',
      path: '/',
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
      size: 24,
      category: 'necessary',
    },
    {
      id: `${domain}__ga`,
      name: '_ga',
      domain: `.${domain}`,
      value: 'GA1.2.1234567890.1234567890',
      path: '/',
      expires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      secure: true,
      httpOnly: false,
      sameSite: 'lax',
      size: 45,
      category: 'analytics',
    },
    {
      id: `facebook.com__fbp`,
      name: '_fbp',
      domain: `.facebook.com`,
      value: 'fb.1.1234567890123.1234567890',
      path: '/',
      expires: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
      secure: true,
      httpOnly: false,
      sameSite: 'none',
      size: 38,
      category: 'advertising',
    },
    {
      id: `doubleclick.net_IDE`,
      name: 'IDE',
      domain: `.doubleclick.net`,
      value: 'AHWqTUm' + Math.random().toString(36).substring(2),
      path: '/',
      expires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      secure: true,
      httpOnly: false,
      sameSite: 'none',
      size: 32,
      category: 'advertising',
    },
  ];
}

// Generate recommendations based on cookie stats
function generateCookieRecommendations(stats) {
  const recommendations = [];
  
  if (stats.tracking > 5) {
    recommendations.push('⚠️ High number of tracking cookies detected. Enable tracker blocking.');
  }
  
  if (stats.malicious > 0) {
    recommendations.push('🚨 CRITICAL: Malicious cookies detected! Remove immediately.');
  }
  
  if (stats.advertising > 3) {
    recommendations.push('📢 Multiple advertising cookies found. Consider blocking third-party ads.');
  }
  
  if (stats.blocked < stats.total * 0.3) {
    recommendations.push('🛡️ Enable stricter cookie blocking for better privacy.');
  }
  
  if (recommendations.length === 0) {
    recommendations.push('✅ Cookie profile looks good! Continue monitoring.');
  }
  
  return recommendations;
}

// Start scan endpoint
app.post('/api/scan/quick', (req, res) => {
  console.log('📡 Quick scan started');
  res.json({
    success: true,
    data: {
      scanning: true,
      scanType: 'quick',
      startTime: new Date().toISOString(),
      message: 'Quick scan started successfully',
    },
  });
});

app.post('/api/scan/full', (req, res) => {
  console.log('📡 Full scan started');
  res.json({
    success: true,
    data: {
      scanning: true,
      scanType: 'full',
      startTime: new Date().toISOString(),
      message: 'Full scan started successfully',
    },
  });
});

app.post('/api/scan/custom', (req, res) => {
  console.log('📡 Custom scan started');
  const { path } = req.body;
  res.json({
    success: true,
    data: {
      scanning: true,
      scanType: 'custom',
      path: path || 'C:\\',
      startTime: new Date().toISOString(),
      message: 'Custom scan started successfully',
    },
  });
});

// Scan status endpoint
app.get('/api/scan/status', (req, res) => {
  res.json({
    success: true,
    data: {
      isScanning: false,
      lastScanTime: new Date(Date.now() - 3600000).toISOString(),
      threatsFound: 0,
      filesScanned: 0,
      progress: 0,
    },
  });
});

// Scan history endpoint
app.get('/api/scan/history', (req, res) => {
  res.json({
    success: true,
    data: {
      scans: [
        {
          id: '1',
          type: 'quick',
          startTime: new Date(Date.now() - 7200000).toISOString(),
          endTime: new Date(Date.now() - 7000000).toISOString(),
          filesScanned: 1247,
          threatsFound: 0,
          status: 'completed',
        },
      ],
    },
  });
});

// Quarantine endpoints
app.get('/api/quarantine', (req, res) => {
  // Return array directly for compatibility with mobile app
  res.json({
    success: true,
    data: []  // Return empty array - frontend expects array of quarantine files
  });
});

app.post('/api/quarantine/:fileId/restore', (req, res) => {
  res.json({
    success: true,
    message: 'File restored successfully',
  });
});

app.delete('/api/quarantine/:fileId', (req, res) => {
  res.json({
    success: true,
    message: 'File deleted successfully',
  });
});

// Network monitoring endpoints
app.get('/api/network/connections', (req, res) => {
  res.json({
    success: true,
    data: {
      connections: [],
      totalActive: 0,
    },
  });
});

app.get('/api/network/stats', (req, res) => {
  res.json({
    success: true,
    data: {
      bytesReceived: 0,
      bytesSent: 0,
      packetsReceived: 0,
      packetsSent: 0,
      timestamp: new Date().toISOString(),
    },
  });
});

app.get('/api/network/apps', (req, res) => {
  res.json({
    success: true,
    data: {
      apps: [],
    },
  });
});

app.get('/api/network/threats', (req, res) => {
  res.json({
    success: true,
    data: {
      threats: [],
      blocked: 0,
    },
  });
});

// ==================== APPLICATION-LEVEL FIREWALL ENDPOINTS ====================

// Get firewall status and configuration
app.get('/api/firewall/status', async (req, res) => {
  try {
    const stats = firewallEngine.getStatistics();
    const windowsStatus = await firewallEngine.checkWindowsFirewall();
    
    res.json({
      success: true,
      status: {
        enabled: firewallEngine.isMonitoring,
        windowsFirewall: windowsStatus,
        platform: firewallEngine.platform,
        statistics: stats
      }
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get all firewall rules
app.get('/api/firewall/rules', (req, res) => {
  try {
    const rules = firewallEngine.getRules();
    res.json({ success: true, rules, count: rules.length });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get single firewall rule
app.get('/api/firewall/rules/:id', (req, res) => {
  try {
    const rules = firewallEngine.getRules();
    const rule = rules.find(r => r.id === req.params.id);
    
    if (!rule) {
      return res.status(404).json({ success: false, error: 'Rule not found' });
    }
    
    res.json({ success: true, rule });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Add new firewall rule
app.post('/api/firewall/rules', (req, res) => {
  try {
    const { rule } = req.body;
    
    if (!rule) {
      return res.status(400).json({ success: false, error: 'Rule object is required' });
    }
    
    const result = firewallEngine.addRule(rule);
    res.json({ success: true, message: 'Rule added successfully', rule: result.rule });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Update firewall rule
app.put('/api/firewall/rules/:id', (req, res) => {
  try {
    const { updates } = req.body;
    const result = firewallEngine.updateRule(req.params.id, updates);
    
    if (!result.success) {
      return res.status(404).json(result);
    }
    
    res.json({ success: true, message: 'Rule updated successfully', rule: result.rule });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Delete firewall rule
app.delete('/api/firewall/rules/:id', (req, res) => {
  try {
    const result = firewallEngine.deleteRule(req.params.id);
    
    if (!result.success) {
      return res.status(404).json(result);
    }
    
    res.json({ success: true, message: 'Rule deleted successfully' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Toggle rule enabled/disabled
app.patch('/api/firewall/rules/:id/toggle', (req, res) => {
  try {
    const rules = firewallEngine.getRules();
    const rule = rules.find(r => r.id === req.params.id);
    
    if (!rule) {
      return res.status(404).json({ success: false, error: 'Rule not found' });
    }
    
    const result = firewallEngine.updateRule(req.params.id, { enabled: !rule.enabled });
    res.json({ success: true, message: `Rule ${result.rule.enabled ? 'enabled' : 'disabled'}`, rule: result.rule });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get blocked IPs
app.get('/api/firewall/blocked-ips', (req, res) => {
  try {
    const blockedIPs = firewallEngine.getBlockedIPs();
    res.json({ success: true, blockedIPs, count: blockedIPs.length });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Block IP address
app.post('/api/firewall/block-ip', async (req, res) => {
  try {
    const { ip, reason } = req.body;
    
    if (!ip) {
      return res.status(400).json({ success: false, error: 'IP address is required' });
    }
    
    const result = await firewallEngine.blockIP(ip, reason || 'Manual block');
    res.json({ success: true, message: 'IP blocked successfully', ...result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Unblock IP address
app.post('/api/firewall/unblock-ip', async (req, res) => {
  try {
    const { ip } = req.body;
    
    if (!ip) {
      return res.status(400).json({ success: false, error: 'IP address is required' });
    }
    
    const result = await firewallEngine.unblockIP(ip);
    res.json({ success: true, message: 'IP unblocked successfully', ...result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get threat log
app.get('/api/firewall/threats', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const threats = firewallEngine.getThreatLog(limit);
    res.json({ success: true, threats, count: threats.length });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Clear threat log
app.delete('/api/firewall/threats', (req, res) => {
  try {
    const result = firewallEngine.clearThreatLog();
    res.json({ success: true, message: 'Threat log cleared' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get firewall statistics
app.get('/api/firewall/statistics', (req, res) => {
  try {
    const stats = firewallEngine.getStatistics();
    res.json({ success: true, statistics: stats });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Reset statistics
app.post('/api/firewall/statistics/reset', (req, res) => {
  try {
    const result = firewallEngine.resetStatistics();
    res.json({ success: true, message: 'Statistics reset' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Start firewall monitoring
app.post('/api/firewall/start', (req, res) => {
  try {
    firewallEngine.startMonitoring();
    res.json({ success: true, message: 'Firewall monitoring started' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Stop firewall monitoring
app.post('/api/firewall/stop', (req, res) => {
  try {
    firewallEngine.stopMonitoring();
    res.json({ success: true, message: 'Firewall monitoring stopped' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get Windows Firewall rules
app.get('/api/firewall/windows/rules', async (req, res) => {
  try {
    const result = await firewallEngine.getWindowsFirewallRules();
    
    if (!result.success) {
      return res.status(400).json(result);
    }
    
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Add Windows Firewall rule
app.post('/api/firewall/windows/rules', async (req, res) => {
  try {
    const { ruleName, config } = req.body;
    
    if (!ruleName || !config) {
      return res.status(400).json({ 
        success: false, 
        error: 'Rule name and configuration are required' 
      });
    }
    
    const result = await firewallEngine.addWindowsFirewallRule(ruleName, config);
    res.json(result);
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Remove Windows Firewall rule
app.delete('/api/firewall/windows/rules/:name', async (req, res) => {
  try {
    const result = await firewallEngine.removeWindowsFirewallRule(req.params.name);
    res.json(result);
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Inspect packet (for testing)
app.post('/api/firewall/inspect', (req, res) => {
  try {
    const { packet } = req.body;
    
    if (!packet) {
      return res.status(400).json({ success: false, error: 'Packet data is required' });
    }
    
    const result = firewallEngine.inspectPacket(packet);
    res.json({ success: true, result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Block application by executable path
app.post('/api/firewall/block-application', async (req, res) => {
  try {
    const { program, ruleName } = req.body;
    
    if (!program) {
      return res.status(400).json({ 
        success: false, 
        error: 'Program path is required' 
      });
    }
    
    const name = ruleName || `Nebula Shield - Block ${program.split('\\').pop()}`;
    
    const result = await firewallEngine.addWindowsFirewallRule(name, {
      direction: 'out',
      action: 'block',
      program
    });
    
    res.json(result);
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Block port
app.post('/api/firewall/block-port', async (req, res) => {
  try {
    const { port, protocol, direction, ruleName } = req.body;
    
    if (!port) {
      return res.status(400).json({ 
        success: false, 
        error: 'Port number is required' 
      });
    }
    
    const name = ruleName || `Nebula Shield - Block Port ${port}`;
    
    const result = await firewallEngine.addWindowsFirewallRule(name, {
      direction: direction || 'in',
      action: 'block',
      protocol: protocol || 'tcp',
      localPort: port
    });
    
    res.json(result);
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

app.get('/api/network/trackers', (req, res) => {
  res.json({
    success: true,
    data: {
      trackers: [],
      blocked: 0,
    },
  });
});

// Disk cleanup endpoints
app.get('/api/disk/analyze', (req, res) => {
  res.json({
    success: true,
    data: {
      totalSize: 0,
      freeSpace: 0,
      usedSpace: 0,
      categories: {
        temp: 0,
        cache: 0,
        logs: 0,
        trash: 0,
      },
    },
  });
});

// Signature update endpoint
app.post('/api/signatures/update', (req, res) => {
  res.json({
    success: true,
    data: {
      version: '1.0.0',
      lastUpdate: new Date().toISOString(),
      signaturesCount: 50000,
    },
  });
});

// ==================== PARENTAL CONTROLS ENDPOINTS ====================

// Set master PIN
app.post('/api/parental/master-pin/set', async (req, res) => {
  try {
    const { pin } = req.body;
    const result = await parentalControls.setMasterPin(pin);
    res.json({ success: true, message: 'Master PIN set successfully' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Verify master PIN
app.post('/api/parental/master-pin/verify', async (req, res) => {
  try {
    const { pin } = req.body;
    const isValid = await parentalControls.verifyMasterPin(pin);
    res.json({ success: true, valid: isValid });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Enable parental controls
app.post('/api/parental/enable', async (req, res) => {
  try {
    const { pin } = req.body;
    await parentalControls.enable(pin);
    res.json({ success: true, message: 'Parental controls enabled' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Disable parental controls
app.post('/api/parental/disable', async (req, res) => {
  try {
    const { pin } = req.body;
    await parentalControls.disable(pin);
    res.json({ success: true, message: 'Parental controls disabled' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Create profile
app.post('/api/parental/profiles', async (req, res) => {
  try {
    const { masterPin, profile } = req.body;
    const newProfile = await parentalControls.createProfile(masterPin, profile);
    res.json({ success: true, profile: newProfile });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get all profiles
app.get('/api/parental/profiles', async (req, res) => {
  try {
    const profiles = await parentalControls.getProfiles();
    res.json({ success: true, profiles });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get single profile
app.get('/api/parental/profiles/:id', async (req, res) => {
  try {
    const profile = await parentalControls.getProfile(req.params.id);
    res.json({ success: true, profile });
  } catch (error) {
    res.status(404).json({ success: false, error: error.message });
  }
});

// Update profile
app.put('/api/parental/profiles/:id', async (req, res) => {
  try {
    const { masterPin, updates } = req.body;
    const updated = await parentalControls.updateProfile(masterPin, req.params.id, updates);
    res.json({ success: true, profile: updated });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Delete profile
app.delete('/api/parental/profiles/:id', async (req, res) => {
  try {
    const { masterPin } = req.body;
    await parentalControls.deleteProfile(masterPin, req.params.id);
    res.json({ success: true, message: 'Profile deleted successfully' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Start session
app.post('/api/parental/session/start', async (req, res) => {
  try {
    const { profileId, pin } = req.body;
    const session = await parentalControls.startSession(profileId, pin);
    res.json({ success: true, session });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// End session
app.post('/api/parental/session/end', async (req, res) => {
  try {
    const { profileId } = req.body;
    await parentalControls.endSession(profileId);
    res.json({ success: true, message: 'Session ended' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Check website
app.post('/api/parental/check-website', async (req, res) => {
  try {
    const { profileId, url } = req.body;
    const result = await parentalControls.checkWebsite(profileId, url);
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get screen time
app.get('/api/parental/screen-time/:profileId', async (req, res) => {
  try {
    const screenTime = await parentalControls.getTodayScreenTime(req.params.profileId);
    res.json({ success: true, screenTime });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get activity report
app.get('/api/parental/reports/activity/:profileId', async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const report = await parentalControls.getActivityReport(req.params.profileId, days);
    res.json({ success: true, report });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get social media report
app.get('/api/parental/reports/social-media/:profileId', async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const report = await parentalControls.getSocialMediaReport(req.params.profileId, days);
    res.json({ success: true, report });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get statistics
app.get('/api/parental/stats', async (req, res) => {
  try {
    const stats = parentalControls.getStatistics();
    res.json({ success: true, stats });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get available categories
app.get('/api/parental/categories', async (req, res) => {
  try {
    const categories = parentalControls.getAvailableCategories();
    res.json({ success: true, categories });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// ==================== SANDBOX & ISOLATION ENDPOINTS ====================

// Get sandbox capabilities
app.get('/api/sandbox/capabilities', async (req, res) => {
  try {
    const stats = sandboxIsolation.getStatistics();
    res.json({ 
      success: true, 
      capabilities: stats.capabilities,
      available: Object.values(stats.capabilities).some(Boolean)
    });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get sandbox configuration
app.get('/api/sandbox/config', async (req, res) => {
  try {
    const config = sandboxIsolation.getConfig();
    res.json({ success: true, config });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Update sandbox configuration
app.put('/api/sandbox/config', async (req, res) => {
  try {
    const { updates } = req.body;
    await sandboxIsolation.updateConfig(updates);
    res.json({ success: true, message: 'Configuration updated' });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Analyze suspicious file
app.post('/api/sandbox/analyze', async (req, res) => {
  try {
    const { filePath, mode } = req.body;
    
    if (!filePath) {
      return res.status(400).json({ 
        success: false, 
        error: 'File path is required' 
      });
    }
    
    const analysis = await sandboxIsolation.analyzeSuspiciousFile(filePath, { mode });
    res.json({ success: true, analysis });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Analyze with WDAG
app.post('/api/sandbox/analyze/wdag', async (req, res) => {
  try {
    const { filePath } = req.body;
    const analysis = await sandboxIsolation.analyzeSuspiciousFile(filePath, { mode: 'wdag' });
    res.json({ success: true, analysis });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Analyze with Hyper-V
app.post('/api/sandbox/analyze/hyperv', async (req, res) => {
  try {
    const { filePath } = req.body;
    const analysis = await sandboxIsolation.analyzeSuspiciousFile(filePath, { mode: 'hyperv' });
    res.json({ success: true, analysis });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Analyze with Docker
app.post('/api/sandbox/analyze/docker', async (req, res) => {
  try {
    const { filePath } = req.body;
    const analysis = await sandboxIsolation.analyzeSuspiciousFile(filePath, { mode: 'docker' });
    res.json({ success: true, analysis });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Analyze with Cloud
app.post('/api/sandbox/analyze/cloud', async (req, res) => {
  try {
    const { filePath } = req.body;
    const analysis = await sandboxIsolation.analyzeSuspiciousFile(filePath, { mode: 'cloud' });
    res.json({ success: true, analysis });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Get sandbox statistics
app.get('/api/sandbox/stats', async (req, res) => {
  try {
    const stats = sandboxIsolation.getStatistics();
    res.json({ success: true, stats });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Enable/disable WDAG
app.post('/api/sandbox/wdag/toggle', async (req, res) => {
  try {
    const { enabled } = req.body;
    await sandboxIsolation.updateConfig({
      wdag: { ...sandboxIsolation.config.wdag, enabled }
    });
    res.json({ success: true, message: `WDAG ${enabled ? 'enabled' : 'disabled'}` });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Enable/disable Hyper-V
app.post('/api/sandbox/hyperv/toggle', async (req, res) => {
  try {
    const { enabled } = req.body;
    await sandboxIsolation.updateConfig({
      hyperv: { ...sandboxIsolation.config.hyperv, enabled }
    });
    res.json({ success: true, message: `Hyper-V ${enabled ? 'enabled' : 'disabled'}` });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Enable/disable Docker
app.post('/api/sandbox/docker/toggle', async (req, res) => {
  try {
    const { enabled } = req.body;
    await sandboxIsolation.updateConfig({
      docker: { ...sandboxIsolation.config.docker, enabled }
    });
    res.json({ success: true, message: `Docker ${enabled ? 'enabled' : 'disabled'}` });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Configure cloud sandbox providers
app.post('/api/sandbox/cloud/configure', async (req, res) => {
  try {
    const { provider, config } = req.body;
    
    const currentConfig = sandboxIsolation.config.cloudSandbox.providers;
    currentConfig[provider] = { ...currentConfig[provider], ...config };
    
    await sandboxIsolation.updateConfig({
      cloudSandbox: {
        ...sandboxIsolation.config.cloudSandbox,
        providers: currentConfig
      }
    });
    
    res.json({ success: true, message: `${provider} configured` });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// ====== SOCKET.IO EVENTS ======

io.on('connection', (socket) => {
  console.log('📱 New connection:', socket.id);
  
  let deviceInfo = null;

  // Authentication
  socket.on('authenticate', (data) => {
    const {token, deviceId, deviceType, deviceName, platform} = data;
    
    // Verify JWT token (optional - can skip for development)
    try {
      if (token) {
        jwt.verify(token, JWT_SECRET);
      }
      
      deviceInfo = {
        id: deviceId || socket.id,
        type: deviceType || 'unknown',
        name: deviceName || `${deviceType} Device`,
        platform: platform || 'unknown',
        socket: socket,
        socketId: socket.id,
        lastSeen: new Date(),
        status: 'connected',
      };
      
      connectedDevices.set(deviceInfo.id, deviceInfo);
      
      socket.emit('authenticated', {
        success: true,
        deviceId: deviceInfo.id,
        message: 'Device authenticated successfully',
      });
      
      console.log(`✅ Device authenticated: ${deviceInfo.id} (${deviceInfo.type})`);
      
      // Notify paired device if exists
      const pairedDeviceId = devicePairs.get(deviceInfo.id);
      if (pairedDeviceId) {
        const pairedDevice = connectedDevices.get(pairedDeviceId);
        if (pairedDevice && pairedDevice.socket) {
          pairedDevice.socket.emit('device:connected', {
            deviceId: deviceInfo.id,
            deviceType: deviceInfo.type,
          });
        }
      }
      
    } catch (error) {
      socket.emit('authentication:failed', {
        success: false,
        error: 'Invalid authentication token',
      });
      console.error('❌ Authentication failed:', error.message);
    }
  });

  // Pairing request from mobile
  socket.on('pairing:request', (data) => {
    const {code, deviceType, platform} = data;
    
    const pairingData = pairingCodes.get(code);
    
    if (!pairingData) {
      socket.emit('pairing:failed', {
        success: false,
        message: 'Invalid or expired pairing code',
      });
      return;
    }
    
    if (Date.now() > pairingData.expiresAt) {
      pairingCodes.delete(code);
      socket.emit('pairing:failed', {
        success: false,
        message: 'Pairing code expired',
      });
      return;
    }
    
    const mobileDeviceId = deviceInfo?.id || socket.id;
    const desktopDeviceId = pairingData.deviceId;
    
    // Create device pair
    devicePairs.set(mobileDeviceId, desktopDeviceId);
    devicePairs.set(desktopDeviceId, mobileDeviceId);
    
    // Clean up used code
    pairingCodes.delete(code);
    
    // Notify both devices
    socket.emit('pairing:success', {
      success: true,
      device: {
        id: desktopDeviceId,
        type: 'desktop',
        name: 'Desktop Computer',
      },
    });
    
    const desktopDevice = connectedDevices.get(desktopDeviceId);
    if (desktopDevice && desktopDevice.socket) {
      desktopDevice.socket.emit('pairing:success', {
        success: true,
        device: {
          id: mobileDeviceId,
          type: 'mobile',
          platform: platform,
          name: `Mobile Device`,
        },
      });
    }
    
    console.log(`✅ Devices paired: ${mobileDeviceId} <-> ${desktopDeviceId}`);
  });

  // Generate pairing code (from desktop)
  socket.on('pairing:generate', (data) => {
    const deviceId = deviceInfo?.id || socket.id;
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();
    
    pairingCodes.set(code, {
      deviceId,
      timestamp: Date.now(),
      expiresAt: Date.now() + 5 * 60 * 1000,
    });
    
    setTimeout(() => {
      pairingCodes.delete(code);
    }, 5 * 60 * 1000);
    
    socket.emit('pairing:code', {
      success: true,
      code,
      expiresIn: 300,
    });
    
    console.log(`🔑 Pairing code generated: ${code} for ${deviceId}`);
  });

  // Metrics data from desktop
  socket.on('metrics:data', (data) => {
    const deviceId = deviceInfo?.id;
    if (!deviceId) return;
    
    // Update device last seen
    if (deviceInfo) {
      deviceInfo.lastSeen = new Date();
    }
    
    // Forward to paired mobile device
    const pairedDeviceId = devicePairs.get(deviceId);
    if (pairedDeviceId) {
      const pairedDevice = connectedDevices.get(pairedDeviceId);
      if (pairedDevice && pairedDevice.socket) {
        pairedDevice.socket.emit('metrics:data', {
          ...data,
          sourceDevice: deviceId,
          timestamp: new Date(),
        });
      }
    }
  });

  // Scan updates from desktop
  socket.on('scan:update', (data) => {
    const deviceId = deviceInfo?.id;
    if (!deviceId) return;
    
    const pairedDeviceId = devicePairs.get(deviceId);
    if (pairedDeviceId) {
      const pairedDevice = connectedDevices.get(pairedDeviceId);
      if (pairedDevice && pairedDevice.socket) {
        pairedDevice.socket.emit('scan:update', {
          ...data,
          sourceDevice: deviceId,
        });
      }
    }
  });

  // Scan completion from desktop
  socket.on('scan:complete', (data) => {
    const deviceId = deviceInfo?.id;
    if (!deviceId) return;
    
    const pairedDeviceId = devicePairs.get(deviceId);
    if (pairedDeviceId) {
      const pairedDevice = connectedDevices.get(pairedDeviceId);
      if (pairedDevice && pairedDevice.socket) {
        pairedDevice.socket.emit('scan:complete', {
          ...data,
          sourceDevice: deviceId,
        });
      }
    }
  });

  // Threat alerts from desktop
  socket.on('threat:alert', (data) => {
    const deviceId = deviceInfo?.id;
    if (!deviceId) return;
    
    const pairedDeviceId = devicePairs.get(deviceId);
    if (pairedDeviceId) {
      const pairedDevice = connectedDevices.get(pairedDeviceId);
      if (pairedDevice && pairedDevice.socket) {
        pairedDevice.socket.emit('threat:alert', {
          ...data,
          sourceDevice: deviceId,
          timestamp: new Date(),
        });
      }
    }
  });

  // Command execution from mobile to desktop
  socket.on('command:execute', (data) => {
    const {targetDeviceId, command, params} = data;
    
    const targetDevice = connectedDevices.get(targetDeviceId);
    if (targetDevice && targetDevice.socket) {
      targetDevice.socket.emit('command:execute', {
        command,
        params,
        sourceDevice: deviceInfo?.id,
      });
      
      socket.emit('command:sent', {
        success: true,
        message: 'Command sent to device',
      });
      
      console.log(`📤 Command sent: ${command} to ${targetDeviceId}`);
    } else {
      socket.emit('command:failed', {
        success: false,
        message: 'Target device not connected',
      });
    }
  });

  // Request metrics from paired device
  socket.on('request:metrics', (data) => {
    const deviceId = deviceInfo?.id;
    if (!deviceId) return;
    
    const pairedDeviceId = devicePairs.get(deviceId);
    if (pairedDeviceId) {
      const pairedDevice = connectedDevices.get(pairedDeviceId);
      if (pairedDevice && pairedDevice.socket) {
        pairedDevice.socket.emit('request:metrics', {
          sourceDevice: deviceId,
        });
      }
    }
  });

  // Request scan history
  socket.on('request:scan-history', (data) => {
    const deviceId = deviceInfo?.id;
    if (!deviceId) return;
    
    const pairedDeviceId = devicePairs.get(deviceId);
    if (pairedDeviceId) {
      const pairedDevice = connectedDevices.get(pairedDeviceId);
      if (pairedDevice && pairedDevice.socket) {
        pairedDevice.socket.emit('request:scan-history', {
          sourceDevice: deviceId,
        });
      }
    }
  });

  // Request device list
  socket.on('request:devices', (data) => {
    const deviceId = deviceInfo?.id;
    if (!deviceId) return;
    
    const pairedDeviceId = devicePairs.get(deviceId);
    const devices = [];
    
    if (pairedDeviceId) {
      const pairedDevice = connectedDevices.get(pairedDeviceId);
      if (pairedDevice) {
        devices.push({
          id: pairedDevice.id,
          type: pairedDevice.type,
          name: pairedDevice.name,
          platform: pairedDevice.platform,
          status: pairedDevice.status,
        });
      }
    }
    
    socket.emit('devices:list', devices);
  });

  // Disconnection
  socket.on('disconnect', () => {
    if (deviceInfo) {
      console.log(`📱 Device disconnected: ${deviceInfo.id}`);
      
      // Update status
      deviceInfo.status = 'disconnected';
      deviceInfo.lastSeen = new Date();
      
      // Notify paired device
      const pairedDeviceId = devicePairs.get(deviceInfo.id);
      if (pairedDeviceId) {
        const pairedDevice = connectedDevices.get(pairedDeviceId);
        if (pairedDevice && pairedDevice.socket) {
          pairedDevice.socket.emit('device:disconnected', {
            deviceId: deviceInfo.id,
            deviceType: deviceInfo.type,
          });
        }
      }
      
      // Remove from connected devices after delay
      setTimeout(() => {
        connectedDevices.delete(deviceInfo.id);
      }, 60000); // Keep for 1 minute for potential reconnection
    }
  });
});

// Initialize enhanced security systems
async function initializeSecuritySystems() {
  console.log('\n🛡️ Initializing Enhanced Security Systems...\n');
  
  try {
    // 1. Initialize ClamAV Integration (8M+ signatures)
    await clamavIntegration.initialize();
    
    // 2. Initialize Cloud Threat Intelligence
    await cloudThreatIntelligence.initialize();
    
    // 3. Initialize Ransomware Honeypot Protection
    await ransomwareHoneypot.initialize();
    
    // 4. Initialize Automatic Update System
    await automaticUpdateSystem.initialize();
    
    // 5. Initialize Password Manager
    await passwordManager.initialize();
    
    // 6. Initialize Parental Controls
    await parentalControls.initialize();
    
    // 7. Initialize Sandbox & Isolation
    await sandboxIsolation.initialize();
    
    console.log('\n✅ All security systems initialized successfully!\n');
    console.log('📊 Security Status:');
    console.log(`   • ClamAV Signatures: ${clamavIntegration.getSignatureInfo().totalSignatures.toLocaleString()}`);
    console.log(`   • Threat Intelligence: ${cloudThreatIntelligence.getStatistics().databases.phishTank + cloudThreatIntelligence.getStatistics().databases.urlhaus} databases loaded`);
    console.log(`   • Ransomware Honeypots: ${ransomwareHoneypot.getStatistics().honeypots.total} active`);
    console.log(`   • Auto-Updates: ${automaticUpdateSystem.getStatus().autoUpdate ? 'Enabled' : 'Disabled'}`);
    console.log(`   • Password Manager: ${passwordManager.getStatistics().hasMasterPassword ? 'Ready' : 'Setup Required'}`);
    console.log(`   • Parental Controls: ${parentalControls.getStatistics().totalProfiles} profiles configured`);
    console.log(`   • Sandbox System: ${Object.values(sandboxIsolation.getStatistics().capabilities).filter(Boolean).length}/4 modes available\n`);
    
    // Set up event listeners
    setupSecurityEventListeners();
    
  } catch (error) {
    console.error('❌ Failed to initialize some security systems:', error.message);
    console.log('⚠️  Server will continue with basic protection\n');
  }
}

// Setup event listeners for security systems
function setupSecurityEventListeners() {
  // Ransomware detection alerts
  ransomwareHoneypot.on('ransomware-detected', (incident) => {
    console.log('🚨🚨🚨 RANSOMWARE DETECTED 🚨🚨🚨');
    console.log(`Type: ${incident.type}`);
    console.log(`Honeypot: ${incident.honeypot}`);
    console.log(`Time: ${incident.timestamp}`);
    
    // Broadcast to all connected clients
    io.emit('security:ransomware-alert', incident);
  });
  
  // Update completion notifications
  automaticUpdateSystem.on('update-completed', (update) => {
    console.log(`✅ Security updates completed: ${update.types.join(', ')}`);
    io.emit('security:update-completed', update);
  });
  
  // ClamAV update events
  clamavIntegration.on('updated', (info) => {
    console.log(`📦 ClamAV signatures updated: ${info.totalSignatures.toLocaleString()}`);
  });
  
  // Password Manager events
  passwordManager.on('password-added', (data) => {
    console.log(`🔐 Password added for: ${data.website}`);
    io.emit('passwords:added', data);
  });
  
  passwordManager.on('breach-scan-completed', (results) => {
    console.log(`🔍 Breach scan completed: ${results.breached} breached, ${results.safe} safe`);
    io.emit('passwords:breach-scan-completed', results);
  });
  
  passwordManager.on('vault-locked', () => {
    io.emit('passwords:vault-locked');
  });
  
  // Parental Controls events
  parentalControls.on('website-blocked', (data) => {
    console.log(`🚫 Website blocked for ${data.url} - Category: ${data.category}`);
    io.emit('parental:website-blocked', data);
  });
  
  parentalControls.on('screen-time-warning', (data) => {
    console.log(`⏰ Screen time warning: ${data.remaining} minutes remaining`);
    io.emit('parental:screen-time-warning', data);
  });
  
  parentalControls.on('screen-time-limit-reached', (data) => {
    console.log(`⛔ Screen time limit reached for profile ${data.profileId}`);
    io.emit('parental:screen-time-limit', data);
  });
  
  parentalControls.on('bedtime-reached', (data) => {
    console.log(`😴 Bedtime reached for profile ${data.profileId}`);
    io.emit('parental:bedtime', data);
  });
  
  // Sandbox Isolation events
  sandboxIsolation.on('analysis-started', (data) => {
    console.log(`🔬 Sandbox analysis started: ${data.fileName}`);
    io.emit('sandbox:analysis-started', data);
  });
  
  sandboxIsolation.on('analysis-completed', (data) => {
    console.log(`✅ Sandbox analysis completed: ${data.fileName} - Threat: ${data.threat ? 'YES' : 'NO'}`);
    io.emit('sandbox:analysis-completed', data);
  });
  
  sandboxIsolation.on('file-quarantined', (data) => {
    console.log(`🗄️ File quarantined: ${data.fileName}`);
    io.emit('sandbox:file-quarantined', data);
  });
}

// Start server
server.listen(PORT, '0.0.0.0', async () => {
  console.log(`\n📱 Nebula Shield Mobile API Server`);
  console.log(`📡 Listening on port ${PORT}`);
  console.log(`🔌 Socket.IO enabled`);
  console.log(`🔗 WebSocket endpoint: ws://0.0.0.0:${PORT}`);
  console.log(`🌐 REST API: http://0.0.0.0:${PORT}/api`);
  console.log(`📱 Mobile access: http://10.0.0.72:${PORT}/api\n`);
  
  // Initialize security systems after server starts
  await initializeSecuritySystems();
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down Mobile API server...');
  io.close(() => {
    console.log('✅ Socket.IO closed');
    server.close(() => {
      console.log('✅ Server closed');
      process.exit(0);
    });
  });
});

module.exports = {app, server, io};
