import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import QRCode from 'qrcode';
import {
  Settings as SettingsIcon,
  Shield,
  Zap,
  Database,
  Bell,
  Download,
  HardDrive,
  Clock,
  Eye,
  Lock,
  RefreshCw,
  Save,
  RotateCcw,
  AlertTriangle,
  CheckCircle,
  Info,
  Sun,
  Moon,
  Calendar,
  Type,
  Maximize2,
  Circle,
  Aperture,
  Upload,
  Monitor,
  X,
  Copy,
  Smartphone
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../contexts/AuthContext';
import AntivirusAPI from '../services/antivirusApi';
import notificationService from '../services/notificationService';
import PremiumFeature from './PremiumFeature';
import toast from 'react-hot-toast';
import './Settings.css';

const Settings = ({ onShowSplash }) => {
  const { 
    theme, 
    toggleTheme, 
    isDark, 
    setPresetTheme,
    themePresets,
    currentThemeConfig,
    fontSize,
    setFontSize,
    spacing,
    setSpacing,
    borderRadius,
    setBorderRadius,
    animationSpeed,
    setAnimationSpeed,
    autoTheme,
    setAutoTheme,
    autoThemeSchedule,
    setAutoThemeSchedule,
    systemThemeSync,
    setSystemThemeSync,
    exportThemeSettings,
    importThemeSettings
  } = useTheme();
  const { isPremium, loadSettings: loadUserSettings, saveSettings: saveUserSettings } = useAuth();
  const [activeTab, setActiveTab] = useState('protection');
  const [settings, setSettings] = useState({
    // Protection Settings
    realTimeProtection: false,
    scanDownloads: true,
    scanUSB: true,
    autoQuarantine: true,
    heuristicAnalysis: true,
    
    // Scan Settings
    maxFileSize: 100, // MB
    timeoutSeconds: 30,
    scanArchives: true,
    deepScan: false,
    skipLargeFiles: false,
    
    // Scheduler Settings
    scheduledScansEnabled: false,
    scanFrequency: 'daily', // daily, weekly, monthly
    scanTime: '02:00',
    scheduledScanType: 'quick', // quick, full
    
    // Database Settings
    autoCleanup: true,
    cleanupDays: 30,
    autoBackup: true,
    backupFrequency: 'weekly',
    
    // Notification Settings
    showNotifications: true,
    soundAlerts: true,
    emailAlerts: false,
    emailAddress: '',
    
    // Update Settings
    autoUpdate: true,
    updateFrequency: 'daily',
    downloadInBackground: true,
    
    // Advanced Settings
    logLevel: 'info',
    enableTelemetry: true,
    serverPort: 8080,
    corsEnabled: true,
    
    // Security Settings
    passwordProtection: false,
    requireAuthForActions: false,
    twoFactorEnabled: false,
    blockSuspiciousConnections: true,
    sandboxUnknownFiles: false,
    enableRansomwareShield: true,
    enableWebProtection: true,
    
    // Performance Settings
    cpuPriority: 'normal', // low, normal, high
    maxCpuUsage: 50, // percentage
    enableCaching: true,
    cacheSize: 256, // MB
    parallelScans: 4,
    
    // Privacy Settings
    anonymizeData: true,
    shareThreats: true,
    collectCrashReports: true,
    clearHistoryOnExit: false
  });
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  const [storageInfo, setStorageInfo] = useState(null);
  const [systemHealth, setSystemHealth] = useState(null);
  const [performanceStats, setPerformanceStats] = useState(null);
  const [showQuickActions, setShowQuickActions] = useState(true);
  
  // 2FA Modal State
  const [show2FAModal, setShow2FAModal] = useState(false);
  const [twoFactorQRCode, setTwoFactorQRCode] = useState('');
  const [twoFactorSecret, setTwoFactorSecret] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [setting2FA, setSetting2FA] = useState(false);
  
  // Password Confirmation Modal State
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [passwordConfirmation, setPasswordConfirmation] = useState('');
  const [passwordError, setPasswordError] = useState('');

  useEffect(() => {
    loadSettings();
    loadStorageInfo();
    const interval = setInterval(() => {
      loadStorageInfo();
      // Also refresh real-time protection status
      syncRealTimeProtectionStatus();
    }, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const loadSettings = async () => {
    try {
      // Load user-specific settings from auth server
      const userSettings = await loadUserSettings();
      
      // Load system config and status with fallbacks
      let config = {};
      let status = { real_time_protection: false };
      
      try {
        [config, status] = await Promise.all([
          AntivirusAPI.getConfiguration(),
          AntivirusAPI.getSystemStatus()
        ]);
      } catch (apiError) {
        console.warn('Failed to load from backend, using defaults:', apiError.message);
        // getConfiguration already has fallback built in
        config = await AntivirusAPI.getConfiguration();
        status = await AntivirusAPI.getSystemStatus();
      }
      
      // Merge user settings with system settings
      setSettings(prevSettings => ({
        ...prevSettings,
        ...config,
        ...(userSettings || {}), // Override with user's saved settings
        // Always sync real-time protection from actual system status
        realTimeProtection: status.real_time_protection || false
      }));
      
      console.log('Settings loaded successfully');
    } catch (error) {
      console.error('Settings load error:', error);
      // Don't show error toast - settings will use defaults
      toast.info('Using default settings (backend unavailable)', { duration: 3000 });
    } finally {
      setLoading(false);
    }
  };

  const syncRealTimeProtectionStatus = async () => {
    try {
      const status = await AntivirusAPI.getSystemStatus();
      setSettings(prev => ({
        ...prev,
        realTimeProtection: status.real_time_protection || false
      }));
    } catch (error) {
      console.error('Failed to sync protection status:', error);
    }
  };

  const loadStorageInfo = async () => {
    try {
      const info = await AntivirusAPI.getStorageInfo();
      setStorageInfo(info);
    } catch (error) {
      console.error('Storage info error:', error);
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const handleSettingChange = (key, value) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }));
    setHasChanges(true);
    
    // Immediately toggle real-time protection when changed
    if (key === 'realTimeProtection') {
      toggleProtectionImmediate(value);
    }
    
    // Handle 2FA toggle
    if (key === 'twoFactorEnabled') {
      handle2FAToggle(value);
    }
  };

  const handle2FAToggle = async (enabled) => {
    if (enabled) {
      // Open modal to set up 2FA
      await initiate2FASetup();
    } else {
      // Show password confirmation modal
      setShowPasswordModal(true);
    }
  };
  
  const confirmDisable2FA = async () => {
    if (!passwordConfirmation) {
      setPasswordError('Password is required');
      return;
    }
    
    try {
      await disable2FA(passwordConfirmation);
      setShowPasswordModal(false);
      setPasswordConfirmation('');
      setPasswordError('');
    } catch (error) {
      setPasswordError('Failed to disable 2FA');
    }
  };
  
  const cancelPasswordModal = () => {
    setShowPasswordModal(false);
    setPasswordConfirmation('');
    setPasswordError('');
    // Revert the toggle
    setSettings(prev => ({
      ...prev,
      twoFactorEnabled: true
    }));
  };

  const initiate2FASetup = async () => {
    try {
      setSetting2FA(true);
      
      // Generate QR code and secret from backend
      // For now, generate mock data for demo
      const mockSecret = 'JBSWY3DPEHPK3PXP'; // Base32 encoded secret
      const appName = 'Nebula Shield';
      const userEmail = 'user@example.com'; // Get from auth context
      
      // Create OTP auth URL
      const otpAuthUrl = `otpauth://totp/${encodeURIComponent(appName)}:${encodeURIComponent(userEmail)}?secret=${mockSecret}&issuer=${encodeURIComponent(appName)}`;
      
      // Generate QR code as data URL
      const qrCodeDataUrl = await generateQRCode(otpAuthUrl);
      
      setTwoFactorSecret(mockSecret);
      setTwoFactorQRCode(qrCodeDataUrl);
      setShow2FAModal(true);
      
      // TODO: Call actual backend API
      // const response = await enable2FA();
      // setTwoFactorSecret(response.secret);
      // setTwoFactorQRCode(response.qrCode);
      
    } catch (error) {
      console.error('Failed to initiate 2FA setup:', error);
      toast.error('Failed to start 2FA setup. Please try again.');
      setSettings(prev => ({
        ...prev,
        twoFactorEnabled: false
      }));
    } finally {
      setSetting2FA(false);
    }
  };

  const generateQRCode = async (text) => {
    // Generate QR code as data URL using qrcode library
    try {
      // Generate QR code as base64 data URL
      const qrDataUrl = await QRCode.toDataURL(text, {
        width: 250,
        margin: 2,
        color: {
          dark: '#000000',
          light: '#FFFFFF'
        },
        errorCorrectionLevel: 'M'
      });
      console.log('✅ QR Code generated successfully');
      return qrDataUrl;
    } catch (error) {
      console.error('QR code generation failed:', error);
      return '';
    }
  };

  const verify2FACode = async () => {
    if (!verificationCode || verificationCode.length !== 6) {
      toast.error('Please enter a 6-digit code');
      return;
    }

    try {
      setSetting2FA(true);
      
      // TODO: Call actual backend API to verify
      // const response = await confirm2FA(verificationCode);
      
      // Mock verification - in production, backend validates the code
      const isValid = true; // Simulate success
      
      if (isValid) {
        toast.success('🎉 Two-Factor Authentication enabled successfully!');
        setShow2FAModal(false);
        setVerificationCode('');
        setSettings(prev => ({
          ...prev,
          twoFactorEnabled: true
        }));
      } else {
        toast.error('Invalid verification code. Please try again.');
      }
    } catch (error) {
      console.error('2FA verification failed:', error);
      toast.error('Verification failed. Please try again.');
    } finally {
      setSetting2FA(false);
    }
  };

  const disable2FA = async (password) => {
    try {
      setSetting2FA(true);
      
      // TODO: Call actual backend API
      // await disable2FA(password);
      
      toast.success('🔓 Two-Factor Authentication disabled');
      setSettings(prev => ({
        ...prev,
        twoFactorEnabled: false
      }));
    } catch (error) {
      console.error('Failed to disable 2FA:', error);
      toast.error('Failed to disable 2FA. Please check your password.');
      // Revert toggle
      setSettings(prev => ({
        ...prev,
        twoFactorEnabled: true
      }));
    } finally {
      setSetting2FA(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard!');
  };

  const toggleProtectionImmediate = async (enabled) => {
    try {
      // Only toggle if the state is actually changing
      const status = await AntivirusAPI.getSystemStatus();
      if (status.real_time_protection !== enabled) {
        await AntivirusAPI.toggleRealTimeProtection();
        toast.success(
          enabled 
            ? '🛡️ Real-time protection enabled!' 
            : '🔓 Real-time protection disabled',
          { duration: 2000 }
        );
      }
    } catch (error) {
      console.error('Failed to toggle protection:', error);
      // Revert the setting if toggle failed
      setSettings(prev => ({
        ...prev,
        realTimeProtection: !enabled
      }));
    }
  };

  const handleSaveSettings = async () => {
    try {
      setSaving(true);
      
      // Save to backend configuration
      try {
        await AntivirusAPI.updateConfiguration(settings);
      } catch (configError) {
        console.error('Backend config update failed:', configError);
        // Fallback: Save to localStorage
        try {
          localStorage.setItem('nebula_shield_settings', JSON.stringify(settings));
          toast.success('Settings saved locally (backend unavailable)', { duration: 4000 });
          setHasChanges(false);
          return;
        } catch (localError) {
          toast.error('Failed to save settings: ' + (configError.message || 'Backend unavailable'));
          return;
        }
      }
      
      // Save user-specific settings to auth server (persists across sessions)
      const saveResult = await saveUserSettings(settings);
      if (!saveResult.success) {
        console.warn('Failed to persist settings to user account:', saveResult.message || saveResult.error);
        // Show warning but still count as success since backend config was updated
        toast.success('Settings saved (local only - sign in to persist across devices)', { duration: 4000 });
      } else {
        toast.success('Settings saved successfully');
      }
      
      setHasChanges(false);
    } catch (error) {
      toast.error('Failed to save settings: ' + (error.message || 'Unknown error'));
      console.error('Settings save error:', error);
    } finally {
      setSaving(false);
    }
  };

  const handleResetSettings = () => {
    if (window.confirm('Reset all settings to default values? This action cannot be undone.')) {
      loadSettings();
      setHasChanges(false);
      toast('Settings reset to defaults', { icon: 'ℹ️' });
    }
  };

  const tabs = [
    { id: 'protection', label: 'Protection', icon: Shield },
    { id: 'security', label: 'Security', icon: Lock },
    { id: 'scanning', label: 'Scanning', icon: Eye },
    { id: 'performance', label: 'Performance', icon: Zap },
    { id: 'scheduler', label: 'Scheduler', icon: Calendar },
    { id: 'appearance', label: 'Appearance', icon: isDark ? Moon : Sun },
    { id: 'privacy', label: 'Privacy', icon: Eye },
    { id: 'database', label: 'Database', icon: Database },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'updates', label: 'Updates', icon: Download },
    { id: 'advanced', label: 'Advanced', icon: SettingsIcon }
  ];

  const renderProtectionSettings = () => (
    <div className="settings-section">
      <div className="section-header">
        <Shield size={24} />
        <div>
          <h3>Protection Settings</h3>
          <p>Configure real-time protection and security features</p>
        </div>
      </div>
      
      <div className="setting-groups">
        <div className="setting-group">
          <h4>Real-time Protection</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Enable Real-time Protection</label>
              <span>Monitor file system changes in real-time</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.realTimeProtection}
                  onChange={(e) => handleSettingChange('realTimeProtection', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Scan Downloads</label>
              <span>Automatically scan downloaded files</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.scanDownloads}
                  onChange={(e) => handleSettingChange('scanDownloads', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Scan USB Devices</label>
              <span>Scan removable drives when connected</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.scanUSB}
                  onChange={(e) => handleSettingChange('scanUSB', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>
        
        <div className="setting-group">
          <h4>Threat Response</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Auto Quarantine</label>
              <span>Automatically quarantine detected threats</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.autoQuarantine}
                  onChange={(e) => handleSettingChange('autoQuarantine', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Heuristic Analysis</label>
              <span>Use advanced heuristics to detect unknown threats</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.heuristicAnalysis}
                  onChange={(e) => handleSettingChange('heuristicAnalysis', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderScanningSettings = () => (
    <div className="settings-section">
      <div className="section-header">
        <Eye size={24} />
        <div>
          <h3>Scanning Settings</h3>
          <p>Configure scan behavior and performance</p>
        </div>
      </div>
      
      <div className="setting-groups">
        <div className="setting-group">
          <h4>Scan Limits</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Maximum File Size (MB)</label>
              <span>Files larger than this will be skipped</span>
            </div>
            <div className="setting-control">
              <input
                type="number"
                min="1"
                max="1000"
                value={settings.maxFileSize}
                onChange={(e) => handleSettingChange('maxFileSize', parseInt(e.target.value))}
                className="number-input"
              />
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Scan Timeout (seconds)</label>
              <span>Maximum time to spend scanning a single file</span>
            </div>
            <div className="setting-control">
              <input
                type="number"
                min="5"
                max="300"
                value={settings.timeoutSeconds}
                onChange={(e) => handleSettingChange('timeoutSeconds', parseInt(e.target.value))}
                className="number-input"
              />
            </div>
          </div>
        </div>
        
        <div className="setting-group">
          <h4>Scan Options</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Scan Archives</label>
              <span>Scan inside ZIP, RAR and other archive files</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.scanArchives}
                  onChange={(e) => handleSettingChange('scanArchives', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Deep Scan</label>
              <span>Perform thorough analysis (slower but more accurate)</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.deepScan}
                  onChange={(e) => handleSettingChange('deepScan', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Skip Large Files</label>
              <span>Skip files larger than the maximum size limit</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.skipLargeFiles}
                  onChange={(e) => handleSettingChange('skipLargeFiles', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderDatabaseSettings = () => (
    <div className="settings-section">
      <div className="section-header">
        <Database size={24} />
        <div>
          <h3>Database Settings</h3>
          <p>Configure data storage and maintenance</p>
        </div>
      </div>
      
      <div className="setting-groups">
        <div className="setting-group">
          <h4>Cleanup</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Auto Cleanup</label>
              <span>Automatically remove old scan results</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.autoCleanup}
                  onChange={(e) => handleSettingChange('autoCleanup', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Cleanup After (days)</label>
              <span>Remove scan results older than this many days</span>
            </div>
            <div className="setting-control">
              <input
                type="number"
                min="1"
                max="365"
                value={settings.cleanupDays}
                onChange={(e) => handleSettingChange('cleanupDays', parseInt(e.target.value))}
                className="number-input"
                disabled={!settings.autoCleanup}
              />
            </div>
          </div>
        </div>
        
        <div className="setting-group">
          <h4>Backup</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Auto Backup</label>
              <span>Automatically backup scan results and settings</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.autoBackup}
                  onChange={(e) => handleSettingChange('autoBackup', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Backup Frequency</label>
              <span>How often to create backups</span>
            </div>
            <div className="setting-control">
              <select
                value={settings.backupFrequency}
                onChange={(e) => handleSettingChange('backupFrequency', e.target.value)}
                className="select-input"
                disabled={!settings.autoBackup}
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderNotificationSettings = () => (
    <div className="settings-section">
      <div className="section-header">
        <Bell size={24} />
        <div>
          <h3>Notification Settings</h3>
          <p>Configure alerts and notifications</p>
        </div>
      </div>
      
      <div className="setting-groups">
        <div className="setting-group">
          <h4>General Notifications</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Show Notifications</label>
              <span>Display desktop notifications for threats and updates</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.showNotifications}
                  onChange={(e) => handleSettingChange('showNotifications', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Sound Alerts</label>
              <span>Play sound when threats are detected</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.soundAlerts}
                  onChange={(e) => handleSettingChange('soundAlerts', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>
        
        <div className="setting-group">
          <h4>Email Alerts</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Email Notifications</label>
              <span>Send email alerts for critical threats</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.emailAlerts}
                  onChange={(e) => handleSettingChange('emailAlerts', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Email Address</label>
              <span>Email address for security alerts</span>
            </div>
            <div className="setting-control">
              <input
                type="email"
                value={settings.emailAddress}
                onChange={(e) => handleSettingChange('emailAddress', e.target.value)}
                className="text-input"
                placeholder="your@email.com"
                disabled={!settings.emailAlerts}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderUpdateSettings = () => (
    <div className="settings-section">
      <div className="section-header">
        <Download size={24} />
        <div>
          <h3>Update Settings</h3>
          <p>Configure automatic updates and signatures</p>
        </div>
      </div>
      
      <div className="setting-groups">
        <div className="setting-group">
          <h4>Automatic Updates</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Auto Update</label>
              <span>Automatically download and install updates</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.autoUpdate}
                  onChange={(e) => handleSettingChange('autoUpdate', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Update Frequency</label>
              <span>How often to check for updates</span>
            </div>
            <div className="setting-control">
              <select
                value={settings.updateFrequency}
                onChange={(e) => handleSettingChange('updateFrequency', e.target.value)}
                className="select-input"
                disabled={!settings.autoUpdate}
              >
                <option value="hourly">Hourly</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Background Downloads</label>
              <span>Download updates in the background</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.downloadInBackground}
                  onChange={(e) => handleSettingChange('downloadInBackground', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderAdvancedSettings = () => (
    <div className="settings-section">
      <div className="section-header">
        <SettingsIcon size={24} />
        <div>
          <h3>Advanced Settings</h3>
          <p>Configure advanced options and debugging</p>
        </div>
      </div>
      
      <div className="setting-groups">
        <div className="setting-group">
          <h4>Logging</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Log Level</label>
              <span>Amount of detail in log files</span>
            </div>
            <div className="setting-control">
              <select
                value={settings.logLevel}
                onChange={(e) => handleSettingChange('logLevel', e.target.value)}
                className="select-input"
              >
                <option value="error">Error</option>
                <option value="warning">Warning</option>
                <option value="info">Info</option>
                <option value="debug">Debug</option>
              </select>
            </div>
          </div>
        </div>
        
        <div className="setting-group">
          <h4>Server Configuration</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Server Port</label>
              <span>Port number for the backend server</span>
            </div>
            <div className="setting-control">
              <input
                type="number"
                min="1024"
                max="65535"
                value={settings.serverPort}
                onChange={(e) => handleSettingChange('serverPort', parseInt(e.target.value))}
                className="number-input"
              />
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>CORS Enabled</label>
              <span>Enable Cross-Origin Resource Sharing</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.corsEnabled}
                  onChange={(e) => handleSettingChange('corsEnabled', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>
        
        <div className="setting-group">
          <h4>Privacy</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Enable Telemetry</label>
              <span>Send anonymous usage data to improve the software</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.enableTelemetry}
                  onChange={(e) => handleSettingChange('enableTelemetry', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>
        
        <div className="setting-group">
          <h4>Demo & Testing</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Show Splash Screen</label>
              <span>Replay the application introduction animation</span>
            </div>
            <div className="setting-control">
              <motion.button
                className="btn btn-secondary"
                onClick={() => onShowSplash && onShowSplash()}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <RefreshCw size={16} />
                Replay Intro
              </motion.button>
            </div>
          </div>
        </div>

        {/* Storage Monitor */}
        <div className="setting-group">
          <h4><HardDrive size={20} /> Storage Monitor</h4>
          {storageInfo ? (
            <>
              <div className="storage-stats">
                <div className="storage-stat-item">
                  <span className="stat-label">Total Space</span>
                  <span className="stat-value">{formatBytes(storageInfo.total_space)}</span>
                </div>
                <div className="storage-stat-item">
                  <span className="stat-label">Used Space</span>
                  <span className="stat-value">{formatBytes(storageInfo.used_space)}</span>
                </div>
                <div className="storage-stat-item">
                  <span className="stat-label">Available Space</span>
                  <span className="stat-value success">{formatBytes(storageInfo.available_space)}</span>
                </div>
              </div>
              
              <div className="storage-bar">
                <div className="storage-bar-fill" style={{ width: `${storageInfo.usage_percentage}%` }}></div>
                <span className="storage-percentage">{storageInfo.usage_percentage.toFixed(1)}% Used</span>
              </div>
              
              <div className="storage-breakdown">
                <div className="breakdown-item">
                  <Info size={14} />
                  <span>Quarantine: {formatBytes(storageInfo.quarantine_size)}</span>
                  <span className={`usage-badge ${storageInfo.quarantine_usage_percentage > 80 ? 'warning' : 'success'}`}>
                    {storageInfo.quarantine_usage_percentage.toFixed(1)}%
                  </span>
                </div>
                <div className="breakdown-item">
                  <Database size={14} />
                  <span>Database: {formatBytes(storageInfo.database_size)}</span>
                </div>
                <div className="breakdown-item">
                  <Download size={14} />
                  <span>Backups: {formatBytes(storageInfo.backup_size)}</span>
                </div>
              </div>
              
              {storageInfo.quarantine_usage_percentage > 80 && (
                <div className="storage-warning">
                  <AlertTriangle size={16} />
                  <span>Quarantine folder is {storageInfo.quarantine_usage_percentage.toFixed(0)}% full. Consider cleaning up old quarantined files.</span>
                </div>
              )}
            </>
          ) : (
            <div className="storage-loading">
              <span>Loading storage information...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  const renderSchedulerSettings = () => (
    <PremiumFeature feature="scheduled-scans">
      <div className="settings-section">
        <div className="section-header">
          <Calendar size={24} />
          <div>
            <h3>Scheduled Scans</h3>
            <p>Configure automatic scanning schedules</p>
          </div>
        </div>
      
      <div className="setting-groups">
        <div className="setting-group">
          <h4>Scan Schedule</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Enable Scheduled Scans</label>
              <span>Automatically run scans at specified times</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.scheduledScansEnabled}
                  onChange={(e) => {
                    handleSettingChange('scheduledScansEnabled', e.target.checked);
                    if (e.target.checked) {
                      notificationService.show('✅ Scheduled Scans Enabled', {
                        body: `${settings.scanFrequency} scans will run at ${settings.scanTime}`
                      });
                    }
                  }}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          {settings.scheduledScansEnabled && (
            <>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Scan Frequency</label>
                  <span>How often to run scheduled scans</span>
                </div>
                <div className="setting-control">
                  <select
                    className="setting-select"
                    value={settings.scanFrequency}
                    onChange={(e) => handleSettingChange('scanFrequency', e.target.value)}
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>
              </div>
              
              <div className="setting-item">
                <div className="setting-info">
                  <label>Scan Time</label>
                  <span>Time of day to run scans (24-hour format)</span>
                </div>
                <div className="setting-control">
                  <input
                    type="time"
                    className="setting-input"
                    value={settings.scanTime}
                    onChange={(e) => handleSettingChange('scanTime', e.target.value)}
                  />
                </div>
              </div>
              
              <div className="setting-item">
                <div className="setting-info">
                  <label>Scan Type</label>
                  <span>Type of scan to perform</span>
                </div>
                <div className="setting-control">
                  <select
                    className="setting-select"
                    value={settings.scheduledScanType}
                    onChange={(e) => handleSettingChange('scheduledScanType', e.target.value)}
                  >
                    <option value="quick">Quick Scan</option>
                    <option value="full">Full System Scan</option>
                  </select>
                </div>
              </div>
              
              <div className="schedule-info">
                <Info size={16} />
                <span>
                  Next scheduled scan: <strong>{settings.scanFrequency}</strong> at <strong>{settings.scanTime}</strong> ({settings.scheduledScanType} scan)
                </span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
    </PremiumFeature>
  );

  const renderSecuritySettings = () => (
    <div className="settings-section">
      <div className="section-header">
        <Lock size={24} />
        <div>
          <h3>Security Settings</h3>
          <p>Enhanced security features and access controls</p>
        </div>
      </div>
      
      <div className="setting-groups">
        <div className="setting-group">
          <h4>Access Control</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Password Protection</label>
              <span>Require password to change settings</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.passwordProtection}
                  onChange={(e) => handleSettingChange('passwordProtection', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Require Authentication</label>
              <span>Require auth for critical actions (quarantine, delete)</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.requireAuthForActions}
                  onChange={(e) => handleSettingChange('requireAuthForActions', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item premium-setting">
            <div className="setting-info">
              <label>
                Two-Factor Authentication (2FA)
                {!isPremium && <span className="premium-badge">Premium</span>}
              </label>
              <span>Add extra security layer with authenticator app</span>
            </div>
            <div className="setting-control">
              {isPremium ? (
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={settings.twoFactorEnabled}
                    onChange={(e) => handleSettingChange('twoFactorEnabled', e.target.checked)}
                  />
                  <span className="slider"></span>
                </label>
              ) : (
                <button className="upgrade-btn" onClick={() => window.location.href = '/#/premium'}>
                  Upgrade
                </button>
              )}
            </div>
          </div>
        </div>
        
        <div className="setting-group">
          <h4>Advanced Protection</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Ransomware Shield</label>
              <span>Monitor and block ransomware encryption attempts</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.enableRansomwareShield}
                  onChange={(e) => handleSettingChange('enableRansomwareShield', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Sandbox Unknown Files</label>
              <span>Run suspicious files in isolated environment</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.sandboxUnknownFiles}
                  onChange={(e) => handleSettingChange('sandboxUnknownFiles', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Web Protection</label>
              <span>Block malicious websites and downloads</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.enableWebProtection}
                  onChange={(e) => handleSettingChange('enableWebProtection', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Block Suspicious Connections</label>
              <span>Automatically block connections to known bad IPs</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.blockSuspiciousConnections}
                  onChange={(e) => handleSettingChange('blockSuspiciousConnections', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderPerformanceSettings = () => (
    <div className="settings-section">
      <div className="section-header">
        <Zap size={24} />
        <div>
          <h3>Performance Settings</h3>
          <p>Optimize resource usage and scanning speed</p>
        </div>
      </div>
      
      <div className="setting-groups">
        <div className="setting-group">
          <h4>Resource Management</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>CPU Priority</label>
              <span>Process priority for scanning operations</span>
            </div>
            <div className="setting-control">
              <select
                value={settings.cpuPriority}
                onChange={(e) => handleSettingChange('cpuPriority', e.target.value)}
                className="select-input"
              >
                <option value="low">Low (Background)</option>
                <option value="normal">Normal (Recommended)</option>
                <option value="high">High (Foreground)</option>
              </select>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Max CPU Usage (%)</label>
              <span>Maximum CPU usage during scans</span>
            </div>
            <div className="setting-control">
              <input
                type="range"
                min="10"
                max="100"
                step="10"
                value={settings.maxCpuUsage}
                onChange={(e) => handleSettingChange('maxCpuUsage', parseInt(e.target.value))}
                className="range-input"
              />
              <span className="range-value">{settings.maxCpuUsage}%</span>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Parallel Scans</label>
              <span>Number of files to scan simultaneously</span>
            </div>
            <div className="setting-control">
              <input
                type="number"
                min="1"
                max="16"
                value={settings.parallelScans}
                onChange={(e) => handleSettingChange('parallelScans', parseInt(e.target.value))}
                className="number-input"
              />
            </div>
          </div>
        </div>
        
        <div className="setting-group">
          <h4>Cache Settings</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Enable Caching</label>
              <span>Cache scan results for faster repeat scans</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.enableCaching}
                  onChange={(e) => handleSettingChange('enableCaching', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Cache Size (MB)</label>
              <span>Maximum cache size for scan results</span>
            </div>
            <div className="setting-control">
              <input
                type="number"
                min="64"
                max="2048"
                step="64"
                value={settings.cacheSize}
                onChange={(e) => handleSettingChange('cacheSize', parseInt(e.target.value))}
                className="number-input"
                disabled={!settings.enableCaching}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderPrivacySettings = () => (
    <div className="settings-section">
      <div className="section-header">
        <Eye size={24} />
        <div>
          <h3>Privacy Settings</h3>
          <p>Control data collection and sharing</p>
        </div>
      </div>
      
      <div className="setting-groups">
        <div className="setting-group">
          <h4>Data Collection</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Anonymize Data</label>
              <span>Remove personal information from reports</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.anonymizeData}
                  onChange={(e) => handleSettingChange('anonymizeData', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Share Threat Intelligence</label>
              <span>Help improve protection by sharing threat data</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.shareThreats}
                  onChange={(e) => handleSettingChange('shareThreats', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Collect Crash Reports</label>
              <span>Send error reports to help fix bugs</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.collectCrashReports}
                  onChange={(e) => handleSettingChange('collectCrashReports', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>
        
        <div className="setting-group">
          <h4>Data Management</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Clear History on Exit</label>
              <span>Delete scan history when closing the application</span>
            </div>
            <div className="setting-control">
              <label className="switch">
                <input
                  type="checkbox"
                  checked={settings.clearHistoryOnExit}
                  onChange={(e) => handleSettingChange('clearHistoryOnExit', e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>
        
        <div className="privacy-notice">
          <Info size={16} />
          <div>
            <strong>Your Privacy Matters</strong>
            <p>We respect your privacy. All data collection is optional and can be disabled. Threat intelligence sharing helps protect all users while keeping your data anonymous.</p>
          </div>
        </div>
      </div>
    </div>
  );

  const renderAppearanceSettings = () => (
    <div className="settings-section">
      <div className="section-header">
        {isDark ? <Moon size={24} /> : <Sun size={24} />}
        <div>
          <h3>Appearance</h3>
          <p>Customize the application look and feel</p>
        </div>
      </div>
      
      <div className="setting-groups">
        {/* Theme Presets */}
        <div className="setting-group">
          <h4>🎨 Theme Presets</h4>
          <p className="setting-description">Choose from our curated color schemes</p>
          
          <div className="theme-grid">
            {Object.entries(themePresets).map(([key, preset]) => (
              <motion.div
                key={key}
                className={`theme-card ${theme === key ? 'active' : ''}`}
                onClick={() => {
                  setPresetTheme(key);
                  toast.success(`Switched to ${preset.name} theme`);
                }}
                whileHover={{ scale: 1.05, y: -5 }}
                whileTap={{ scale: 0.95 }}
              >
                <div className="theme-card-preview">
                  <div 
                    className="theme-color-primary" 
                    style={{ backgroundColor: preset.colors.primary }}
                  />
                  <div 
                    className="theme-color-accent" 
                    style={{ backgroundColor: preset.colors.accent }}
                  />
                  <div 
                    className="theme-color-secondary" 
                    style={{ backgroundColor: preset.colors.accentSecondary }}
                  />
                </div>
                <div className="theme-card-name">{preset.name}</div>
                {theme === key && (
                  <div className="theme-card-active">
                    <CheckCircle size={16} />
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </div>

        {/* Customization */}
        <div className="setting-group">
          <h4>🎛️ Customization</h4>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>
                <Type size={18} />
                Font Size
              </label>
              <span>Adjust text size across the application</span>
            </div>
            <div className="setting-control">
              <select
                value={fontSize}
                onChange={(e) => {
                  setFontSize(e.target.value);
                  toast.success(`Font size changed to ${e.target.value}`);
                }}
                className="select-input"
              >
                <option value="small">Small (14px)</option>
                <option value="normal">Normal (16px)</option>
                <option value="large">Large (18px)</option>
                <option value="extra-large">Extra Large (20px)</option>
              </select>
            </div>
          </div>

          <div className="setting-item">
            <div className="setting-info">
              <label>
                <Maximize2 size={18} />
                Spacing
              </label>
              <span>Control the density of UI elements</span>
            </div>
            <div className="setting-control">
              <select
                value={spacing}
                onChange={(e) => {
                  setSpacing(e.target.value);
                  toast.success(`Spacing changed to ${e.target.value}`);
                }}
                className="select-input"
              >
                <option value="compact">Compact</option>
                <option value="comfortable">Comfortable</option>
                <option value="spacious">Spacious</option>
              </select>
            </div>
          </div>

          <div className="setting-item">
            <div className="setting-info">
              <label>
                <Circle size={18} />
                Border Radius
              </label>
              <span>Adjust the roundness of corners</span>
            </div>
            <div className="setting-control">
              <select
                value={borderRadius}
                onChange={(e) => {
                  setBorderRadius(e.target.value);
                  toast.success(`Border radius changed to ${e.target.value}`);
                }}
                className="select-input"
              >
                <option value="sharp">Sharp (0px)</option>
                <option value="rounded">Rounded (8px)</option>
                <option value="very-rounded">Very Rounded (16px)</option>
              </select>
            </div>
          </div>

          <div className="setting-item">
            <div className="setting-info">
              <label>
                <Zap size={18} />
                Animation Speed
              </label>
              <span>Control animation and transition speeds</span>
            </div>
            <div className="setting-control">
              <select
                value={animationSpeed}
                onChange={(e) => {
                  setAnimationSpeed(e.target.value);
                  toast.success(`Animation speed changed to ${e.target.value}`);
                }}
                className="select-input"
              >
                <option value="none">None (0s)</option>
                <option value="reduced">Reduced (0.15s)</option>
                <option value="normal">Normal (0.3s)</option>
                <option value="enhanced">Enhanced (0.5s)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Auto Theme Switching */}
        <div className="setting-group">
          <h4>⏰ Automatic Theme Switching</h4>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>
                <Clock size={18} />
                Time-Based Switching
              </label>
              <span>Automatically switch themes based on time of day</span>
            </div>
            <div className="setting-control">
              <label className="toggle-switch">
                <input
                  type="checkbox"
                  checked={autoTheme}
                  onChange={(e) => {
                    setAutoTheme(e.target.checked);
                    if (e.target.checked) {
                      toast.success('Auto theme switching enabled');
                    } else {
                      toast.success('Auto theme switching disabled');
                    }
                  }}
                />
                <span className="toggle-slider"></span>
              </label>
            </div>
          </div>

          {autoTheme && (
            <motion.div
              className="auto-theme-schedule"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <div className="schedule-row">
                <div className="schedule-item">
                  <label>Light theme starts at</label>
                  <input
                    type="time"
                    value={autoThemeSchedule.lightStart}
                    onChange={(e) => {
                      setAutoThemeSchedule({
                        ...autoThemeSchedule,
                        lightStart: e.target.value
                      });
                    }}
                    className="time-input"
                  />
                </div>
                <div className="schedule-item">
                  <select
                    value={autoThemeSchedule.lightTheme}
                    onChange={(e) => {
                      setAutoThemeSchedule({
                        ...autoThemeSchedule,
                        lightTheme: e.target.value
                      });
                    }}
                    className="select-input"
                  >
                    {Object.entries(themePresets).map(([key, preset]) => (
                      <option key={key} value={key}>{preset.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="schedule-row">
                <div className="schedule-item">
                  <label>Dark theme starts at</label>
                  <input
                    type="time"
                    value={autoThemeSchedule.darkStart}
                    onChange={(e) => {
                      setAutoThemeSchedule({
                        ...autoThemeSchedule,
                        darkStart: e.target.value
                      });
                    }}
                    className="time-input"
                  />
                </div>
                <div className="schedule-item">
                  <select
                    value={autoThemeSchedule.darkTheme}
                    onChange={(e) => {
                      setAutoThemeSchedule({
                        ...autoThemeSchedule,
                        darkTheme: e.target.value
                      });
                    }}
                    className="select-input"
                  >
                    {Object.entries(themePresets).map(([key, preset]) => (
                      <option key={key} value={key}>{preset.name}</option>
                    ))}
                  </select>
                </div>
              </div>
            </motion.div>
          )}

          <div className="setting-item">
            <div className="setting-info">
              <label>
                <Monitor size={18} />
                System Theme Sync
              </label>
              <span>Follow your operating system theme preference</span>
            </div>
            <div className="setting-control">
              <label className="toggle-switch">
                <input
                  type="checkbox"
                  checked={systemThemeSync}
                  onChange={(e) => {
                    setSystemThemeSync(e.target.checked);
                    if (e.target.checked) {
                      toast.success('System theme sync enabled');
                    } else {
                      toast.success('System theme sync disabled');
                    }
                  }}
                />
                <span className="toggle-slider"></span>
              </label>
            </div>
          </div>
        </div>

        {/* Theme Import/Export */}
        <div className="setting-group">
          <h4>💾 Theme Settings</h4>
          
          <div className="setting-item">
            <div className="setting-info">
              <label>Export Theme Settings</label>
              <span>Save your theme configuration to a file</span>
            </div>
            <div className="setting-control">
              <motion.button
                className="btn btn-secondary"
                onClick={() => {
                  const settings = exportThemeSettings();
                  const blob = new Blob([JSON.stringify(settings, null, 2)], {
                    type: 'application/json'
                  });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `nebula-shield-theme-${new Date().toISOString().split('T')[0]}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                  toast.success('Theme settings exported!');
                }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <Download size={16} />
                Export Settings
              </motion.button>
            </div>
          </div>

          <div className="setting-item">
            <div className="setting-info">
              <label>Import Theme Settings</label>
              <span>Load a previously exported theme configuration</span>
            </div>
            <div className="setting-control">
              <motion.button
                className="btn btn-secondary"
                onClick={() => {
                  const input = document.createElement('input');
                  input.type = 'file';
                  input.accept = '.json';
                  input.onchange = async (e) => {
                    const file = e.target.files[0];
                    if (file) {
                      try {
                        const text = await file.text();
                        const settings = JSON.parse(text);
                        importThemeSettings(settings);
                        toast.success('Theme settings imported successfully!');
                      } catch (error) {
                        toast.error('Failed to import theme settings');
                      }
                    }
                  };
                  input.click();
                }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <Upload size={16} />
                Import Settings
              </motion.button>
            </div>
          </div>
        </div>

        {/* Current Theme Preview */}
        <div className="setting-group">
          <h4>🎨 Current Theme Preview</h4>
          <div className="theme-preview-enhanced">
            <div className="preview-header">
              <h5>{currentThemeConfig?.name || 'Custom Theme'}</h5>
              <span className="preview-badge">{isDark ? 'Dark' : 'Light'}</span>
            </div>
            <div className="preview-colors-grid">
              <div className="color-preview-item">
                <div 
                  className="color-preview-swatch" 
                  style={{ backgroundColor: currentThemeConfig?.colors.primary }}
                />
                <span>Primary</span>
              </div>
              <div className="color-preview-item">
                <div 
                  className="color-preview-swatch" 
                  style={{ backgroundColor: currentThemeConfig?.colors.secondary }}
                />
                <span>Secondary</span>
              </div>
              <div className="color-preview-item">
                <div 
                  className="color-preview-swatch" 
                  style={{ backgroundColor: currentThemeConfig?.colors.accent }}
                />
                <span>Accent</span>
              </div>
              <div className="color-preview-item">
                <div 
                  className="color-preview-swatch" 
                  style={{ backgroundColor: currentThemeConfig?.colors.success }}
                />
                <span>Success</span>
              </div>
              <div className="color-preview-item">
                <div 
                  className="color-preview-swatch" 
                  style={{ backgroundColor: currentThemeConfig?.colors.warning }}
                />
                <span>Warning</span>
              </div>
              <div className="color-preview-item">
                <div 
                  className="color-preview-swatch" 
                  style={{ backgroundColor: currentThemeConfig?.colors.danger }}
                />
                <span>Danger</span>
              </div>
            </div>
            <div className="preview-info">
              <Info size={16} />
              <span>Font: {fontSize} • Spacing: {spacing} • Radius: {borderRadius} • Animation: {animationSpeed}</span>
            </div>
          </div>
        </div>
        
        <div className="setting-group">
          <h4>Notifications</h4>
          <div className="setting-item">
            <div className="setting-info">
              <label>Desktop Notifications</label>
              <span>Enable system notifications for threats and scans</span>
            </div>
            <div className="setting-control">
              <motion.button
                className={`btn ${notificationService.isEnabled() ? 'btn-success' : notificationService.isDenied() ? 'btn-warning' : 'btn-secondary'}`}
                onClick={async () => {
                  // Check if already denied
                  if (notificationService.isDenied()) {
                    toast.error(
                      'Notification permission was blocked. Please enable it in your browser settings:\n' +
                      '1. Click the lock icon in the address bar\n' +
                      '2. Find "Notifications" and set to "Allow"\n' +
                      '3. Reload the page',
                      { duration: 8000 }
                    );
                    return;
                  }

                  const granted = await notificationService.requestPermission();
                  if (granted) {
                    toast.success('Desktop notifications enabled');
                    notificationService.show('🎉 Notifications Enabled!', {
                      body: 'You will now receive desktop notifications'
                    });
                  } else {
                    toast.error(
                      'Notification permission denied. To enable:\n' +
                      '1. Click the lock/info icon in your browser address bar\n' +
                      '2. Set Notifications to "Allow"\n' +
                      '3. Reload this page',
                      { duration: 8000 }
                    );
                  }
                }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                {notificationService.isEnabled() ? (
                  <>
                    <CheckCircle size={16} />
                    Enabled
                  </>
                ) : notificationService.isDenied() ? (
                  <>
                    <AlertTriangle size={16} />
                    Blocked - Click for Help
                  </>
                ) : (
                  <>
                    <Bell size={16} />
                    Enable Notifications
                  </>
                )}
              </motion.button>
            </div>
          </div>

          {/* Show help message when notifications are blocked */}
          {notificationService.isDenied() && (
            <motion.div
              className="notification-blocked-help"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              style={{
                marginTop: '12px',
                padding: '16px',
                background: 'rgba(245, 158, 11, 0.1)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                borderRadius: '8px',
                fontSize: '13px',
                lineHeight: '1.6'
              }}
            >
              <div style={{ display: 'flex', gap: '12px', alignItems: 'start' }}>
                <AlertTriangle size={20} style={{ color: '#f59e0b', flexShrink: 0, marginTop: '2px' }} />
                <div>
                  <strong style={{ color: '#f59e0b', display: 'block', marginBottom: '8px' }}>
                    How to Enable Notifications:
                  </strong>
                  <ol style={{ margin: '0', paddingLeft: '20px', color: 'var(--text-secondary)' }}>
                    <li>Look for the 🔒 lock icon or ℹ️ info icon in your browser's address bar (top left)</li>
                    <li>Click it to open the site permissions menu</li>
                    <li>Find "Notifications" in the list</li>
                    <li>Change it from "Block" to "Allow"</li>
                    <li>Reload this page (press F5 or Ctrl+R)</li>
                    <li>Click the "Enable Notifications" button again</li>
                  </ol>
                  <div style={{ marginTop: '12px', padding: '8px', background: 'rgba(0,0,0,0.2)', borderRadius: '4px', fontSize: '12px' }}>
                    💡 <strong>Tip:</strong> If you don't see a "Notifications" option, your browser may have blocked all notifications. 
                    Check your browser's main settings under Privacy → Site Settings → Notifications.
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </div>

        {/* Storage Monitor */}
        <div className="setting-group">
          <h4><HardDrive size={20} /> Storage Monitor</h4>
          {storageInfo ? (
            <>
              <div className="storage-stats">
                <div className="storage-stat-item">
                  <span className="stat-label">Total Space</span>
                  <span className="stat-value">{formatBytes(storageInfo.total_space)}</span>
                </div>
                <div className="storage-stat-item">
                  <span className="stat-label">Used Space</span>
                  <span className="stat-value">{formatBytes(storageInfo.used_space)}</span>
                </div>
                <div className="storage-stat-item">
                  <span className="stat-label">Available Space</span>
                  <span className="stat-value success">{formatBytes(storageInfo.available_space)}</span>
                </div>
              </div>
              
              <div className="storage-bar">
                <div className="storage-bar-fill" style={{ width: `${storageInfo.usage_percentage}%` }}></div>
                <span className="storage-percentage">{storageInfo.usage_percentage.toFixed(1)}% Used</span>
              </div>
              
              <div className="storage-breakdown">
                <div className="breakdown-item">
                  <Info size={14} />
                  <span>Quarantine: {formatBytes(storageInfo.quarantine_size)}</span>
                  <span className={`usage-badge ${storageInfo.quarantine_usage_percentage > 80 ? 'warning' : 'success'}`}>
                    {storageInfo.quarantine_usage_percentage.toFixed(1)}%
                  </span>
                </div>
                <div className="breakdown-item">
                  <Database size={14} />
                  <span>Database: {formatBytes(storageInfo.database_size)}</span>
                </div>
                <div className="breakdown-item">
                  <Download size={14} />
                  <span>Backups: {formatBytes(storageInfo.backup_size)}</span>
                </div>
              </div>
              
              {storageInfo.quarantine_usage_percentage > 80 && (
                <div className="storage-warning">
                  <AlertTriangle size={16} />
                  <span>Quarantine folder is {storageInfo.quarantine_usage_percentage.toFixed(0)}% full. Consider cleaning up old quarantined files.</span>
                </div>
              )}
            </>
          ) : (
            <div className="storage-loading">
              <span>Loading storage information...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  const renderTabContent = () => {
    switch (activeTab) {
      case 'protection': return renderProtectionSettings();
      case 'security': return renderSecuritySettings();
      case 'scanning': return renderScanningSettings();
      case 'performance': return renderPerformanceSettings();
      case 'scheduler': return renderSchedulerSettings();
      case 'appearance': return renderAppearanceSettings();
      case 'privacy': return renderPrivacySettings();
      case 'database': return renderDatabaseSettings();
      case 'notifications': return renderNotificationSettings();
      case 'updates': return renderUpdateSettings();
      case 'advanced': return renderAdvancedSettings();
      default: return renderProtectionSettings();
    }
  };

  if (loading) {
    return (
      <div className="settings-loading">
        <div className="loading-content">
          <div className="spinner"></div>
          <p>Loading settings...</p>
        </div>
      </div>
    );
  }

  // Get current tab info for dynamic header
  const getCurrentTabInfo = () => {
    const tabInfo = {
      protection: { title: 'Protection Settings', subtitle: 'Configure real-time protection and security features' },
      security: { title: 'Security & Access Control', subtitle: 'Advanced security features and authentication' },
      scanning: { title: 'Scanning Configuration', subtitle: 'Customize scan behavior and file handling' },
      performance: { title: 'Performance Tuning', subtitle: 'Optimize resource usage and scanning speed' },
      scheduler: { title: 'Scheduled Scans', subtitle: 'Automate your security with scheduled scanning' },
      appearance: { title: 'Appearance', subtitle: 'Customize theme and visual preferences' },
      privacy: { title: 'Privacy Controls', subtitle: 'Manage data collection and privacy settings' },
      database: { title: 'Database Management', subtitle: 'Manage virus definitions and scan history' },
      notifications: { title: 'Notifications', subtitle: 'Configure alerts and notification preferences' },
      updates: { title: 'Updates', subtitle: 'Manage automatic updates and signature downloads' },
      advanced: { title: 'Advanced Settings', subtitle: 'Server configuration and advanced options' }
    };
    return tabInfo[activeTab] || tabInfo.protection;
  };

  const currentTab = getCurrentTabInfo();

  return (
    <motion.div
      className="settings"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
    >
      {/* Page Header - Dynamic based on active tab */}
      <div className="page-header">
        <motion.h1
          className="page-title"
          key={activeTab + '-title'}
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.1 }}
        >
          {currentTab.title}
        </motion.h1>
        <motion.p
          className="page-subtitle"
          key={activeTab + '-subtitle'}
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
        >
          {currentTab.subtitle}
        </motion.p>
      </div>

      <div className="settings-layout">
        {/* Sidebar Navigation */}
        <motion.div
          className="settings-sidebar"
          initial={{ x: -20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ delay: 0.3 }}
        >
          <nav className="settings-nav">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <motion.button
                  key={tab.id}
                  className={`nav-item ${activeTab === tab.id ? 'active' : ''}`}
                  onClick={() => setActiveTab(tab.id)}
                  whileHover={{ x: 4 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <Icon size={20} />
                  <span>{tab.label}</span>
                </motion.button>
              );
            })}
          </nav>
        </motion.div>

        {/* Settings Content */}
        <motion.div
          className="settings-content"
          initial={{ x: 20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ delay: 0.4 }}
        >
          {renderTabContent()}
        </motion.div>
      </div>

      {/* Save Actions */}
      {hasChanges && (
        <motion.div
          className="settings-actions"
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
        >
          <div className="actions-content">
            <div className="actions-info">
              <AlertTriangle size={20} />
              <span>You have unsaved changes</span>
            </div>
            <div className="actions-buttons">
              <motion.button
                className="btn btn-secondary"
                onClick={handleResetSettings}
                disabled={saving}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <RotateCcw size={16} />
                Reset
              </motion.button>
              <motion.button
                className="btn btn-primary"
                onClick={handleSaveSettings}
                disabled={saving}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                {saving ? (
                  <>
                    <RefreshCw size={16} className="spinning" />
                    Saving...
                  </>
                ) : (
                  <>
                    <Save size={16} />
                    Save Changes
                  </>
                )}
              </motion.button>
            </div>
          </div>
        </motion.div>
      )}
      
      {/* 2FA Setup Modal */}
      <AnimatePresence>
        {show2FAModal && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShow2FAModal(false)}
          >
            <motion.div
              className="modal-content twofa-modal"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header">
                <div className="modal-title">
                  <Smartphone size={24} />
                  <h3>Enable Two-Factor Authentication</h3>
                </div>
                <button
                  className="modal-close"
                  onClick={() => {
                    setShow2FAModal(false);
                    setSettings(prev => ({ ...prev, twoFactorEnabled: false }));
                  }}
                >
                  <X size={20} />
                </button>
              </div>

              <div className="modal-body">
                <div className="twofa-steps">
                  <div className="step">
                    <div className="step-number">1</div>
                    <div className="step-content">
                      <h4>Install an Authenticator App</h4>
                      <p>Download Google Authenticator, Authy, or any TOTP-compatible app</p>
                    </div>
                  </div>

                  <div className="step">
                    <div className="step-number">2</div>
                    <div className="step-content">
                      <h4>Scan QR Code</h4>
                      <p>Open your authenticator app and scan this QR code</p>
                      
                      {twoFactorQRCode && (
                        <div className="qr-code-container">
                          <img src={twoFactorQRCode} alt="2FA QR Code" className="qr-code" />
                        </div>
                      )}

                      <div className="secret-key">
                        <p>Or enter this key manually:</p>
                        <div className="secret-value">
                          <code>{twoFactorSecret}</code>
                          <button
                            className="copy-btn"
                            onClick={() => copyToClipboard(twoFactorSecret)}
                          >
                            <Copy size={16} />
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="step">
                    <div className="step-number">3</div>
                    <div className="step-content">
                      <h4>Verify Code</h4>
                      <p>Enter the 6-digit code from your authenticator app</p>
                      
                      <div className="verification-input">
                        <input
                          type="text"
                          placeholder="000000"
                          maxLength={6}
                          value={verificationCode}
                          onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, ''))}
                          className="code-input"
                          autoFocus
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="modal-footer">
                <button
                  className="btn btn-secondary"
                  onClick={() => {
                    setShow2FAModal(false);
                    setSettings(prev => ({ ...prev, twoFactorEnabled: false }));
                  }}
                  disabled={setting2FA}
                >
                  Cancel
                </button>
                <button
                  className="btn btn-primary"
                  onClick={verify2FACode}
                  disabled={setting2FA || verificationCode.length !== 6}
                >
                  {setting2FA ? (
                    <>
                      <RefreshCw size={16} className="spinning" />
                      Verifying...
                    </>
                  ) : (
                    <>
                      <CheckCircle size={16} />
                      Verify & Enable
                    </>
                  )}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Password Confirmation Modal */}
      <AnimatePresence>
        {showPasswordModal && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={cancelPasswordModal}
          >
            <motion.div
              className="modal-content password-modal"
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.8, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header">
                <h3>
                  <Lock size={24} />
                  Disable Two-Factor Authentication
                </h3>
                <button className="close-btn" onClick={cancelPasswordModal}>
                  <X size={20} />
                </button>
              </div>

              <div className="modal-body">
                <div className="password-confirm-section">
                  <p className="warning-text">
                    <AlertTriangle size={18} />
                    You are about to disable Two-Factor Authentication. This will reduce your account security.
                  </p>
                  
                  <div className="form-group">
                    <label htmlFor="password-confirm">Enter your password to confirm:</label>
                    <input
                      id="password-confirm"
                      type="password"
                      className={`form-control ${passwordError ? 'error' : ''}`}
                      value={passwordConfirmation}
                      onChange={(e) => {
                        setPasswordConfirmation(e.target.value);
                        setPasswordError('');
                      }}
                      onKeyPress={(e) => {
                        if (e.key === 'Enter') {
                          confirmDisable2FA();
                        }
                      }}
                      placeholder="Enter your password"
                      autoFocus
                    />
                    {passwordError && (
                      <span className="error-message">{passwordError}</span>
                    )}
                  </div>
                </div>
              </div>

              <div className="modal-footer">
                <button
                  className="btn btn-secondary"
                  onClick={cancelPasswordModal}
                  disabled={setting2FA}
                >
                  Cancel
                </button>
                <button
                  className="btn btn-danger"
                  onClick={confirmDisable2FA}
                  disabled={setting2FA || !passwordConfirmation}
                >
                  {setting2FA ? (
                    <>
                      <RefreshCw size={16} className="spinning" />
                      Disabling...
                    </>
                  ) : (
                    <>
                      <Lock size={16} />
                      Disable 2FA
                    </>
                  )}
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

export default Settings;