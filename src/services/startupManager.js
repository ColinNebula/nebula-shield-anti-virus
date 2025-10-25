/**
 * Startup Manager Service
 * 
 * Scans and manages Windows startup programs to reduce boot time and system clutter.
 * Provides startup item detection, impact analysis, and optimization recommendations.
 * 
 * Features:
 * - Scan startup programs from multiple locations
 * - Analyze startup impact (time, memory, CPU)
 * - Categorize by necessity (Critical, Recommended, Optional, Bloatware)
 * - Enable/disable startup items
 * - Backup and restore startup configuration
 */

class StartupManager {
  constructor() {
    this.startupLocations = {
      // Windows Registry Run keys
      registry: [
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
      ],
      
      // Startup folders
      folders: [
        '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
        '%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
      ],
      
      // Task Scheduler
      tasks: [
        '\\Microsoft\\Windows\\StartUp'
      ],
      
      // Services (Windows Services that start automatically)
      services: [
        'Automatic',
        'Automatic (Delayed Start)'
      ]
    };

    // Known bloatware and unnecessary startup programs
    this.bloatwareList = [
      // Adobe updaters
      { name: /Adobe.*Updater/i, category: 'bloatware', reason: 'Updater runs in background unnecessarily' },
      { name: /AdobeAAM.*Updater/i, category: 'bloatware', reason: 'Adobe Application Manager updater' },
      
      // Update checkers
      { name: /CCleaner.*Monitoring/i, category: 'bloatware', reason: 'Monitoring not needed at startup' },
      { name: /Java.*Update/i, category: 'bloatware', reason: 'Can check manually when needed' },
      { name: /Apple.*Update/i, category: 'bloatware', reason: 'iTunes/QuickTime updater' },
      
      // Toolbars and adware
      { name: /Ask.*Toolbar/i, category: 'bloatware', reason: 'Unnecessary toolbar' },
      { name: /Babylon.*Toolbar/i, category: 'bloatware', reason: 'Adware toolbar' },
      { name: /Conduit/i, category: 'bloatware', reason: 'Adware/toolbar' },
      
      // Manufacturer bloatware
      { name: /HP.*Support.*Assistant/i, category: 'optional', reason: 'Can be started when needed' },
      { name: /Dell.*SupportAssist/i, category: 'optional', reason: 'Support tool not needed at startup' },
      { name: /Lenovo.*Vantage/i, category: 'optional', reason: 'Can be started manually' },
      
      // Chat/messaging startup
      { name: /Skype/i, category: 'optional', reason: 'Start manually when needed' },
      { name: /Discord.*Update/i, category: 'optional', reason: 'Discord will auto-update when opened' },
      { name: /Spotify.*WebHelper/i, category: 'optional', reason: 'Not needed at startup' },
      
      // Cloud sync
      { name: /OneDrive/i, category: 'optional', reason: 'Can delay or disable if not using' },
      { name: /Dropbox.*Update/i, category: 'optional', reason: 'Updates when app starts' },
      
      // System tray bloat
      { name: /Realtek.*HD.*Audio/i, category: 'optional', reason: 'Audio still works without tray icon' },
      { name: /NVIDIA.*GeForce.*Experience/i, category: 'optional', reason: 'Gaming overlay, not critical' },
      { name: /Steam.*Client/i, category: 'optional', reason: 'Start manually when gaming' },
      
      // Office telemetry
      { name: /Microsoft.*Office.*Click.*to.*Run/i, category: 'optional', reason: 'Office will work without it' },
      { name: /Microsoft.*Teams.*Update/i, category: 'optional', reason: 'Updates when app starts' }
    ];

    // Critical system programs that should stay enabled
    this.criticalPrograms = [
      // Security
      { name: /Windows.*Defender/i, category: 'critical', reason: 'System security' },
      { name: /Nebula.*Shield/i, category: 'critical', reason: 'Antivirus protection' },
      
      // System drivers
      { name: /Intel.*Graphics/i, category: 'critical', reason: 'Display driver' },
      { name: /AMD.*Catalyst/i, category: 'critical', reason: 'Graphics driver' },
      { name: /NVIDIA.*Display/i, category: 'critical', reason: 'Graphics driver' },
      
      // Audio
      { name: /Windows.*Audio/i, category: 'critical', reason: 'System audio' },
      
      // Input devices
      { name: /Synaptics.*TouchPad/i, category: 'recommended', reason: 'Touchpad driver' },
      { name: /Logitech.*SetPoint/i, category: 'recommended', reason: 'Mouse/keyboard software' }
    ];
  }

  /**
   * Scan all startup programs from registry, folders, and task scheduler
   */
  async scanStartupPrograms() {
    try {
      const startupItems = [];
      
      // Mock data for demonstration (in production, would query actual system)
      const mockStartupData = [
        {
          id: 'startup_1',
          name: 'Adobe Creative Cloud',
          publisher: 'Adobe Inc.',
          command: 'C:\\Program Files\\Adobe\\Adobe Creative Cloud\\ACC\\Creative Cloud.exe',
          location: 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          type: 'Registry',
          status: 'Enabled',
          startupImpact: 'High',
          impactScore: 8.5,
          memoryUsage: 250, // MB
          cpuUsage: 15, // %
          bootDelay: 4.2, // seconds
          lastRun: new Date(Date.now() - 3600000),
          category: 'bloatware',
          recommendation: 'Disable',
          reason: 'Adobe updater runs in background unnecessarily, can be started manually when needed'
        },
        {
          id: 'startup_2',
          name: 'Windows Defender',
          publisher: 'Microsoft Corporation',
          command: 'C:\\Program Files\\Windows Defender\\MSASCuiL.exe',
          location: 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          type: 'Registry',
          status: 'Enabled',
          startupImpact: 'Low',
          impactScore: 2.1,
          memoryUsage: 50,
          cpuUsage: 2,
          bootDelay: 0.8,
          lastRun: new Date(Date.now() - 1800000),
          category: 'critical',
          recommendation: 'Keep Enabled',
          reason: 'Essential for system security'
        },
        {
          id: 'startup_3',
          name: 'OneDrive',
          publisher: 'Microsoft Corporation',
          command: 'C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background',
          location: 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          type: 'Registry',
          status: 'Enabled',
          startupImpact: 'Medium',
          impactScore: 5.3,
          memoryUsage: 120,
          cpuUsage: 8,
          bootDelay: 2.1,
          lastRun: new Date(Date.now() - 7200000),
          category: 'optional',
          recommendation: 'Consider Disabling',
          reason: 'Cloud sync can be delayed or disabled if not actively using'
        },
        {
          id: 'startup_4',
          name: 'Spotify Web Helper',
          publisher: 'Spotify AB',
          command: 'C:\\Users\\User\\AppData\\Roaming\\Spotify\\SpotifyWebHelper.exe',
          location: 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          type: 'Registry',
          status: 'Enabled',
          startupImpact: 'Medium',
          impactScore: 4.7,
          memoryUsage: 85,
          cpuUsage: 5,
          bootDelay: 1.8,
          lastRun: new Date(Date.now() - 5400000),
          category: 'bloatware',
          recommendation: 'Disable',
          reason: 'Not needed at startup, Spotify works fine without it'
        },
        {
          id: 'startup_5',
          name: 'Intel Graphics Settings',
          publisher: 'Intel Corporation',
          command: 'C:\\Program Files\\Intel\\Intel(R) Graphics Settings\\igfxTray.exe',
          location: 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          type: 'Registry',
          status: 'Enabled',
          startupImpact: 'Low',
          impactScore: 3.2,
          memoryUsage: 35,
          cpuUsage: 1,
          bootDelay: 0.5,
          lastRun: new Date(Date.now() - 900000),
          category: 'recommended',
          recommendation: 'Keep Enabled',
          reason: 'Provides quick access to display settings'
        },
        {
          id: 'startup_6',
          name: 'Discord Update',
          publisher: 'Discord Inc.',
          command: 'C:\\Users\\User\\AppData\\Local\\Discord\\Update.exe --processStart Discord.exe',
          location: 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          type: 'Registry',
          status: 'Enabled',
          startupImpact: 'High',
          impactScore: 7.8,
          memoryUsage: 180,
          cpuUsage: 12,
          bootDelay: 3.5,
          lastRun: new Date(Date.now() - 2700000),
          category: 'optional',
          recommendation: 'Disable',
          reason: 'Discord will auto-update when you open it, no need for startup'
        },
        {
          id: 'startup_7',
          name: 'NVIDIA GeForce Experience',
          publisher: 'NVIDIA Corporation',
          command: 'C:\\Program Files\\NVIDIA Corporation\\NVIDIA GeForce Experience\\NVIDIA GeForce Experience.exe',
          location: 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          type: 'Registry',
          status: 'Enabled',
          startupImpact: 'High',
          impactScore: 9.2,
          memoryUsage: 320,
          cpuUsage: 18,
          bootDelay: 5.1,
          lastRun: new Date(Date.now() - 4500000),
          category: 'optional',
          recommendation: 'Disable',
          reason: 'Gaming overlay not needed at startup, start when gaming'
        },
        {
          id: 'startup_8',
          name: 'Realtek HD Audio Manager',
          publisher: 'Realtek Semiconductor',
          command: 'C:\\Program Files\\Realtek\\Audio\\HDA\\RtkNGUI64.exe',
          location: 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          type: 'Registry',
          status: 'Enabled',
          startupImpact: 'Low',
          impactScore: 2.8,
          memoryUsage: 45,
          cpuUsage: 2,
          bootDelay: 0.7,
          lastRun: new Date(Date.now() - 1200000),
          category: 'optional',
          recommendation: 'Consider Disabling',
          reason: 'Audio works without system tray icon, only needed for advanced settings'
        },
        {
          id: 'startup_9',
          name: 'Java Update Scheduler',
          publisher: 'Oracle Corporation',
          command: 'C:\\Program Files\\Common Files\\Java\\Java Update\\jusched.exe',
          location: 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          type: 'Registry',
          status: 'Enabled',
          startupImpact: 'Medium',
          impactScore: 6.1,
          memoryUsage: 95,
          cpuUsage: 7,
          bootDelay: 2.3,
          lastRun: new Date(Date.now() - 6300000),
          category: 'bloatware',
          recommendation: 'Disable',
          reason: 'Can check for Java updates manually when needed'
        },
        {
          id: 'startup_10',
          name: 'Microsoft Teams',
          publisher: 'Microsoft Corporation',
          command: 'C:\\Users\\User\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart "Teams.exe" --process-start-args "--system-initiated"',
          location: 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          type: 'Registry',
          status: 'Enabled',
          startupImpact: 'High',
          impactScore: 8.9,
          memoryUsage: 280,
          cpuUsage: 16,
          bootDelay: 4.8,
          lastRun: new Date(Date.now() - 3900000),
          category: 'optional',
          recommendation: 'Consider Disabling',
          reason: 'Teams can be started manually when needed for meetings'
        }
      ];

      return {
        success: true,
        items: mockStartupData,
        summary: this.analyzeSummary(mockStartupData)
      };

    } catch (error) {
      console.error('Startup scan error:', error);
      return {
        success: false,
        error: error.message,
        items: [],
        summary: null
      };
    }
  }

  /**
   * Analyze startup summary and calculate potential improvements
   */
  analyzeSummary(items) {
    const total = items.length;
    const enabled = items.filter(i => i.status === 'Enabled').length;
    const disabled = total - enabled;
    
    const bloatware = items.filter(i => i.category === 'bloatware').length;
    const optional = items.filter(i => i.category === 'optional').length;
    const recommended = items.filter(i => i.category === 'recommended').length;
    const critical = items.filter(i => i.category === 'critical').length;
    
    const totalBootDelay = items
      .filter(i => i.status === 'Enabled')
      .reduce((sum, i) => sum + i.bootDelay, 0);
    
    const totalMemory = items
      .filter(i => i.status === 'Enabled')
      .reduce((sum, i) => sum + i.memoryUsage, 0);
    
    const disablableItems = items.filter(i => 
      i.status === 'Enabled' && 
      (i.category === 'bloatware' || i.category === 'optional')
    );
    
    const potentialTimeSaved = disablableItems.reduce((sum, i) => sum + i.bootDelay, 0);
    const potentialMemorySaved = disablableItems.reduce((sum, i) => sum + i.memoryUsage, 0);
    
    const highImpactItems = items.filter(i => 
      i.status === 'Enabled' && i.startupImpact === 'High'
    ).length;

    return {
      total,
      enabled,
      disabled,
      categories: {
        bloatware,
        optional,
        recommended,
        critical
      },
      impact: {
        currentBootTime: totalBootDelay.toFixed(1),
        currentMemoryUsage: totalMemory,
        potentialTimeSaved: potentialTimeSaved.toFixed(1),
        potentialMemorySaved: potentialMemorySaved,
        improvementPercentage: ((potentialTimeSaved / totalBootDelay) * 100).toFixed(0),
        highImpactItems
      },
      recommendations: {
        canDisable: disablableItems.length,
        shouldKeep: critical + recommended
      }
    };
  }

  /**
   * Categorize startup item
   */
  categorizeItem(item) {
    // Check if critical
    for (const critical of this.criticalPrograms) {
      if (critical.name.test(item.name)) {
        return {
          category: critical.category,
          recommendation: 'Keep Enabled',
          reason: critical.reason
        };
      }
    }

    // Check if bloatware
    for (const bloat of this.bloatwareList) {
      if (bloat.name.test(item.name)) {
        return {
          category: bloat.category,
          recommendation: bloat.category === 'bloatware' ? 'Disable' : 'Consider Disabling',
          reason: bloat.reason
        };
      }
    }

    // Default: optional
    return {
      category: 'optional',
      recommendation: 'Review',
      reason: 'Review if needed at startup'
    };
  }

  /**
   * Disable a startup item
   */
  async disableStartupItem(itemId) {
    try {
      // In production, would modify registry or move file
      console.log(`Disabling startup item: ${itemId}`);
      
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 500));
      
      return {
        success: true,
        message: 'Startup item disabled successfully',
        itemId
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Enable a startup item
   */
  async enableStartupItem(itemId) {
    try {
      // In production, would restore registry entry or file
      console.log(`Enabling startup item: ${itemId}`);
      
      await new Promise(resolve => setTimeout(resolve, 500));
      
      return {
        success: true,
        message: 'Startup item enabled successfully',
        itemId
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Apply recommended optimizations (disable bloatware)
   */
  async applyRecommendedOptimizations(items) {
    try {
      const itemsToDisable = items.filter(i => 
        i.status === 'Enabled' && 
        (i.category === 'bloatware' || 
         (i.category === 'optional' && i.recommendation === 'Disable'))
      );

      const results = {
        success: true,
        disabled: [],
        failed: [],
        timeSaved: 0,
        memorySaved: 0
      };

      for (const item of itemsToDisable) {
        const result = await this.disableStartupItem(item.id);
        if (result.success) {
          results.disabled.push(item.name);
          results.timeSaved += item.bootDelay;
          results.memorySaved += item.memoryUsage;
        } else {
          results.failed.push({ name: item.name, error: result.error });
        }
      }

      return results;
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Create backup of current startup configuration
   */
  async backupStartupConfig() {
    try {
      const items = await this.scanStartupPrograms();
      
      const backup = {
        timestamp: new Date().toISOString(),
        items: items.items,
        version: '1.0'
      };

      // In production, would save to file or database
      localStorage.setItem('startupBackup', JSON.stringify(backup));

      return {
        success: true,
        backup,
        message: 'Startup configuration backed up successfully'
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Restore startup configuration from backup
   */
  async restoreStartupConfig() {
    try {
      const backupData = localStorage.getItem('startupBackup');
      
      if (!backupData) {
        throw new Error('No backup found');
      }

      const backup = JSON.parse(backupData);

      // In production, would restore registry entries and files
      console.log('Restoring startup configuration from backup:', backup.timestamp);

      return {
        success: true,
        backup,
        message: 'Startup configuration restored successfully'
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get startup optimization score (0-100)
   */
  calculateOptimizationScore(items) {
    if (!items || items.length === 0) return 100;

    const enabled = items.filter(i => i.status === 'Enabled');
    const bloatwareEnabled = enabled.filter(i => i.category === 'bloatware').length;
    const highImpact = enabled.filter(i => i.startupImpact === 'High').length;
    
    // Perfect score if no bloatware and minimal high-impact items
    let score = 100;
    score -= bloatwareEnabled * 15; // -15 points per bloatware
    score -= highImpact * 5; // -5 points per high impact item
    score -= (enabled.length > 10 ? (enabled.length - 10) * 2 : 0); // -2 points for each item over 10

    return Math.max(0, Math.min(100, score));
  }
}

const startupManager = new StartupManager();
export default startupManager;
