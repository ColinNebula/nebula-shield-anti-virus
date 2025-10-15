/**
 * Driver Scanner Service
 * Detects outdated drivers and provides safe update recommendations
 */

// Common driver categories and their known versions
const DRIVER_DATABASE = {
  graphics: {
    nvidia: { latest: '546.17', critical: '536.23', released: '2024-10' },
    amd: { latest: '23.12.1', critical: '23.10.2', released: '2024-11' },
    intel: { latest: '31.0.101.5186', critical: '31.0.101.4502', released: '2024-10' }
  },
  network: {
    intel: { latest: '23.5.2', critical: '23.0.0', released: '2024-09' },
    realtek: { latest: '10.62.1003.2023', critical: '10.60.0', released: '2024-08' },
    qualcomm: { latest: '2.8.0.1051', critical: '2.7.0', released: '2024-10' }
  },
  audio: {
    realtek: { latest: '6.0.9506.1', critical: '6.0.9400.1', released: '2024-09' },
    conexant: { latest: '10.0.332.51', critical: '10.0.300.0', released: '2024-08' }
  },
  chipset: {
    intel: { latest: '10.1.19444.8378', critical: '10.1.19000.0', released: '2024-10' },
    amd: { latest: '5.11.0.2', critical: '5.10.0.0', released: '2024-09' }
  },
  storage: {
    nvme: { latest: '2.8', critical: '2.5', released: '2024-08' },
    sata: { latest: '19.5.1.38', critical: '19.0.0', released: '2024-07' }
  },
  usb: {
    generic: { latest: '10.0.22621.1485', critical: '10.0.22000.0', released: '2024-09' }
  }
};

// Security vulnerabilities database
const KNOWN_VULNERABILITIES = [
  {
    driver: 'NVIDIA Graphics',
    cve: 'CVE-2024-0126',
    severity: 'HIGH',
    affectedVersions: ['< 546.00'],
    description: 'Privilege escalation vulnerability in NVIDIA GPU Display Driver',
    recommendation: 'Update to version 546.17 or later immediately'
  },
  {
    driver: 'Intel Network Adapter',
    cve: 'CVE-2024-21823',
    severity: 'MEDIUM',
    affectedVersions: ['< 23.5.0'],
    description: 'Improper access control in Intel Ethernet Controllers',
    recommendation: 'Update to version 23.5.2 or later'
  },
  {
    driver: 'Realtek Audio',
    cve: 'CVE-2024-27894',
    severity: 'MEDIUM',
    affectedVersions: ['< 6.0.9500.0'],
    description: 'Buffer overflow in Realtek HD Audio Driver',
    recommendation: 'Update to version 6.0.9506.1 or later'
  }
];

/**
 * Simulate driver detection (in production, would use WMI or system APIs)
 */
const detectInstalledDrivers = () => {
  // Simulated driver data - in production would query actual system
  return [
    {
      id: 'drv_001',
      name: 'NVIDIA GeForce RTX 4070',
      category: 'Graphics',
      manufacturer: 'NVIDIA',
      currentVersion: '536.23',
      installedDate: '2024-08-15',
      deviceClass: 'Display adapters',
      hardwareId: 'PCI\\VEN_10DE&DEV_2786'
    },
    {
      id: 'drv_002',
      name: 'Intel(R) Wi-Fi 6 AX200',
      category: 'Network',
      manufacturer: 'Intel',
      currentVersion: '22.240.0.3',
      installedDate: '2024-07-10',
      deviceClass: 'Network adapters',
      hardwareId: 'PCI\\VEN_8086&DEV_2723'
    },
    {
      id: 'drv_003',
      name: 'Realtek High Definition Audio',
      category: 'Audio',
      manufacturer: 'Realtek',
      currentVersion: '6.0.9400.1',
      installedDate: '2024-06-20',
      deviceClass: 'Sound, video and game controllers',
      hardwareId: 'HDAUDIO\\FUNC_01&VEN_10EC'
    },
    {
      id: 'drv_004',
      name: 'Intel Chipset Device Software',
      category: 'Chipset',
      manufacturer: 'Intel',
      currentVersion: '10.1.19444.8378',
      installedDate: '2024-09-01',
      deviceClass: 'System devices',
      hardwareId: 'PCI\\VEN_8086&DEV_A082'
    },
    {
      id: 'drv_005',
      name: 'Samsung NVMe SSD Controller',
      category: 'Storage',
      manufacturer: 'Samsung',
      currentVersion: '2.5',
      installedDate: '2024-05-15',
      deviceClass: 'Disk drives',
      hardwareId: 'SCSI\\DISK&VEN_SAMSUNG'
    },
    {
      id: 'drv_006',
      name: 'AMD Radeon RX 6800 XT',
      category: 'Graphics',
      manufacturer: 'AMD',
      currentVersion: '23.10.2',
      installedDate: '2024-08-20',
      deviceClass: 'Display adapters',
      hardwareId: 'PCI\\VEN_1002&DEV_73BF'
    },
    {
      id: 'drv_007',
      name: 'Realtek PCIe GBE Family Controller',
      category: 'Network',
      manufacturer: 'Realtek',
      currentVersion: '10.62.1003.2023',
      installedDate: '2024-09-10',
      deviceClass: 'Network adapters',
      hardwareId: 'PCI\\VEN_10EC&DEV_8168'
    },
    {
      id: 'drv_008',
      name: 'Intel USB 3.1 eXtensible Host Controller',
      category: 'USB',
      manufacturer: 'Intel',
      currentVersion: '10.0.22000.832',
      installedDate: '2024-07-05',
      deviceClass: 'Universal Serial Bus controllers',
      hardwareId: 'PCI\\VEN_8086&DEV_A36D'
    }
  ];
};

/**
 * Compare version strings
 */
const compareVersions = (current, latest) => {
  const currentParts = current.split('.').map(n => parseInt(n) || 0);
  const latestParts = latest.split('.').map(n => parseInt(n) || 0);
  
  const maxLength = Math.max(currentParts.length, latestParts.length);
  
  for (let i = 0; i < maxLength; i++) {
    const c = currentParts[i] || 0;
    const l = latestParts[i] || 0;
    
    if (c < l) return -1; // current is older
    if (c > l) return 1;  // current is newer
  }
  
  return 0; // versions are equal
};

/**
 * Check for security vulnerabilities
 */
const checkVulnerabilities = (driver) => {
  const vulnerabilities = [];
  
  KNOWN_VULNERABILITIES.forEach(vuln => {
    if (driver.name.includes(vuln.driver.split(' ')[0])) {
      // Simple version check (in production, would be more sophisticated)
      vulnerabilities.push(vuln);
    }
  });
  
  return vulnerabilities;
};

/**
 * Analyze driver and determine update status
 */
const analyzeDriver = (driver) => {
  const manufacturer = driver.manufacturer.toLowerCase();
  const category = driver.category.toLowerCase();
  
  let latestVersion = null;
  let criticalVersion = null;
  let releaseDate = null;
  
  // Find latest version from database
  if (DRIVER_DATABASE[category] && DRIVER_DATABASE[category][manufacturer]) {
    const dbEntry = DRIVER_DATABASE[category][manufacturer];
    latestVersion = dbEntry.latest;
    criticalVersion = dbEntry.critical;
    releaseDate = dbEntry.released;
  }
  
  if (!latestVersion) {
    return {
      ...driver,
      status: 'unknown',
      statusText: 'Version information unavailable',
      updateAvailable: false,
      severity: 'info'
    };
  }
  
  const comparison = compareVersions(driver.currentVersion, latestVersion);
  const vulnerabilities = checkVulnerabilities(driver);
  
  let status, statusText, severity, updateAvailable;
  
  if (comparison < 0) {
    // Current version is older than latest
    const criticalComparison = compareVersions(driver.currentVersion, criticalVersion);
    
    if (vulnerabilities.length > 0) {
      status = 'critical';
      statusText = 'Security vulnerability detected - Update immediately';
      severity = 'critical';
    } else if (criticalComparison < 0) {
      status = 'outdated_critical';
      statusText = 'Critically outdated - Update recommended';
      severity = 'high';
    } else {
      status = 'outdated';
      statusText = 'Update available';
      severity = 'medium';
    }
    updateAvailable = true;
  } else if (comparison === 0) {
    status = 'up_to_date';
    statusText = 'Up to date';
    severity = 'success';
    updateAvailable = false;
  } else {
    status = 'newer';
    statusText = 'Newer than database version';
    severity = 'info';
    updateAvailable = false;
  }
  
  return {
    ...driver,
    latestVersion,
    releaseDate,
    status,
    statusText,
    severity,
    updateAvailable,
    vulnerabilities,
    downloadUrl: getDownloadUrl(driver.manufacturer, category),
    supportUrl: getSupportUrl(driver.manufacturer)
  };
};

/**
 * Get official download URL for driver updates
 */
const getDownloadUrl = (manufacturer, category) => {
  const urls = {
    nvidia: 'https://www.nvidia.com/Download/index.aspx',
    amd: 'https://www.amd.com/en/support',
    intel: 'https://www.intel.com/content/www/us/en/download-center/home.html',
    realtek: 'https://www.realtek.com/en/downloads',
    samsung: 'https://www.samsung.com/semiconductor/minisite/ssd/download/tools/',
    qualcomm: 'https://www.qualcomm.com/support'
  };
  
  return urls[manufacturer.toLowerCase()] || 'https://www.google.com/search?q=' + 
    encodeURIComponent(manufacturer + ' ' + category + ' driver download');
};

/**
 * Get support URL
 */
const getSupportUrl = (manufacturer) => {
  const urls = {
    nvidia: 'https://www.nvidia.com/en-us/support/',
    amd: 'https://www.amd.com/en/support',
    intel: 'https://www.intel.com/content/www/us/en/support.html',
    realtek: 'https://www.realtek.com/en/support',
    samsung: 'https://www.samsung.com/us/support/',
    qualcomm: 'https://www.qualcomm.com/support'
  };
  
  return urls[manufacturer.toLowerCase()] || 'https://www.google.com/search?q=' + 
    encodeURIComponent(manufacturer + ' support');
};

/**
 * Main driver scan function
 */
export const scanDrivers = async () => {
  return new Promise((resolve) => {
    // Simulate scanning delay
    setTimeout(() => {
      const installedDrivers = detectInstalledDrivers();
      const analyzedDrivers = installedDrivers.map(analyzeDriver);
      
      const summary = {
        totalDrivers: analyzedDrivers.length,
        upToDate: analyzedDrivers.filter(d => d.status === 'up_to_date').length,
        outdated: analyzedDrivers.filter(d => d.status === 'outdated').length,
        critical: analyzedDrivers.filter(d => d.status === 'critical' || d.status === 'outdated_critical').length,
        vulnerabilities: analyzedDrivers.reduce((sum, d) => sum + (d.vulnerabilities?.length || 0), 0)
      };
      
      resolve({
        success: true,
        drivers: analyzedDrivers,
        summary,
        scannedAt: new Date().toISOString()
      });
    }, 1500);
  });
};

/**
 * Get driver update recommendations
 */
export const getUpdateRecommendations = (drivers) => {
  const critical = drivers.filter(d => d.severity === 'critical');
  const high = drivers.filter(d => d.severity === 'high');
  const medium = drivers.filter(d => d.severity === 'medium');
  
  return {
    immediate: critical,
    recommended: high,
    optional: medium,
    priorities: [
      ...critical.map(d => ({
        ...d,
        priority: 'CRITICAL',
        reason: 'Security vulnerability or system stability risk'
      })),
      ...high.map(d => ({
        ...d,
        priority: 'HIGH',
        reason: 'Significantly outdated, may cause compatibility issues'
      })),
      ...medium.map(d => ({
        ...d,
        priority: 'MEDIUM',
        reason: 'Update available for improved performance and features'
      }))
    ]
  };
};

/**
 * Create system restore point recommendation
 */
export const getRestorePointAdvice = () => {
  return {
    recommended: true,
    reason: 'Always create a system restore point before updating drivers',
    howTo: [
      'Open System Properties (sysdm.cpl)',
      'Go to System Protection tab',
      'Click "Create..."',
      'Enter a description (e.g., "Before driver updates")',
      'Click "Create" and wait for completion'
    ],
    automaticCommand: 'Checkpoint-Computer -Description "Before driver updates" -RestorePointType "MODIFY_SETTINGS"'
  };
};

export default {
  scanDrivers,
  getUpdateRecommendations,
  getRestorePointAdvice
};
