/**
 * Network Protection Service
 * Real-time network monitoring, firewall management, and intrusion detection
 */

// Known malicious IPs (sample database)
const MALICIOUS_IPS = [
  '185.220.101.1',
  '45.142.122.3',
  '198.98.57.207',
  '91.219.236.197',
  '23.129.64.216',
  '185.220.100.240'
];

// Known command & control servers
const C2_SERVERS = [
  '192.0.2.1',
  '198.51.100.1',
  '203.0.113.1'
];

// Suspicious ports
const SUSPICIOUS_PORTS = {
  outbound: [4444, 5555, 6666, 31337, 12345, 1337, 6667], // Common backdoor/trojan ports
  inbound: [23, 135, 139, 445, 3389, 5900] // Telnet, RPC, SMB, RDP, VNC
};

// GeoIP database (simplified)
const GEO_DATABASE = {
  '8.8.8.8': { country: 'United States', city: 'Mountain View', org: 'Google LLC', flag: '🇺🇸' },
  '1.1.1.1': { country: 'United States', city: 'San Francisco', org: 'Cloudflare', flag: '🇺🇸' },
  '142.250.': { country: 'United States', city: 'Mountain View', org: 'Google LLC', flag: '🇺🇸' },
  '172.217.': { country: 'United States', city: 'Mountain View', org: 'Google LLC', flag: '🇺🇸' },
  '151.101.': { country: 'United States', city: 'San Francisco', org: 'Fastly', flag: '🇺🇸' },
  '104.244.': { country: 'United States', city: 'San Francisco', org: 'Twitter', flag: '🇺🇸' },
  '13.107.': { country: 'United States', city: 'Redmond', org: 'Microsoft', flag: '🇺🇸' },
  '20.190.': { country: 'United States', city: 'Redmond', org: 'Microsoft Azure', flag: '🇺🇸' },
  '185.220.': { country: 'Unknown', city: 'Unknown', org: 'Tor Exit Node', flag: '⚠️' },
  '91.219.': { country: 'Russia', city: 'Moscow', org: 'Unknown ISP', flag: '🇷🇺' }
};

/**
 * Simulate active network connections
 */
const generateActiveConnections = () => {
  const connections = [
    // Browser connections
    {
      id: 'conn_001',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 54321,
      remoteAddress: '142.250.185.46',
      remotePort: 443,
      state: 'ESTABLISHED',
      process: 'chrome.exe',
      pid: 8432,
      direction: 'outbound',
      bandwidth: { sent: 12400, received: 45600 },
      duration: 127,
      threat: null
    },
    {
      id: 'conn_002',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 54322,
      remoteAddress: '151.101.1.140',
      remotePort: 443,
      state: 'ESTABLISHED',
      process: 'chrome.exe',
      pid: 8432,
      direction: 'outbound',
      bandwidth: { sent: 8900, received: 34200 },
      duration: 89,
      threat: null
    },
    // Microsoft services
    {
      id: 'conn_003',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 54323,
      remoteAddress: '13.107.42.16',
      remotePort: 443,
      state: 'ESTABLISHED',
      process: 'MicrosoftEdge.exe',
      pid: 12456,
      direction: 'outbound',
      bandwidth: { sent: 5600, received: 18900 },
      duration: 234,
      threat: null
    },
    // DNS queries
    {
      id: 'conn_004',
      protocol: 'UDP',
      localAddress: '192.168.1.100',
      localPort: 52147,
      remoteAddress: '8.8.8.8',
      remotePort: 53,
      state: 'ACTIVE',
      process: 'svchost.exe',
      pid: 1234,
      direction: 'outbound',
      bandwidth: { sent: 120, received: 240 },
      duration: 2,
      threat: null
    },
    // System updates
    {
      id: 'conn_005',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 54324,
      remoteAddress: '20.190.151.9',
      remotePort: 443,
      state: 'ESTABLISHED',
      process: 'WindowsUpdate.exe',
      pid: 5678,
      direction: 'outbound',
      bandwidth: { sent: 3400, received: 156000 },
      duration: 456,
      threat: null
    },
    // Suspicious Tor connection
    {
      id: 'conn_006',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 54325,
      remoteAddress: '185.220.101.1',
      remotePort: 9001,
      state: 'ESTABLISHED',
      process: 'unknown.exe',
      pid: 9999,
      direction: 'outbound',
      bandwidth: { sent: 45000, received: 23000 },
      duration: 678,
      threat: {
        level: 'high',
        type: 'Tor Exit Node',
        description: 'Connection to known Tor exit node - possible anonymization attempt'
      }
    },
    // Suspicious inbound RDP
    {
      id: 'conn_007',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 3389,
      remoteAddress: '91.219.236.197',
      remotePort: 54891,
      state: 'SYN_RECEIVED',
      process: 'svchost.exe',
      pid: 4,
      direction: 'inbound',
      bandwidth: { sent: 0, received: 120 },
      duration: 1,
      threat: {
        level: 'critical',
        type: 'Suspicious Inbound Connection',
        description: 'Unsolicited RDP connection attempt from suspicious IP'
      }
    },
    // Node.js development server
    {
      id: 'conn_008',
      protocol: 'TCP',
      localAddress: '0.0.0.0',
      localPort: 3000,
      remoteAddress: '*',
      remotePort: 0,
      state: 'LISTENING',
      process: 'node.exe',
      pid: 15234,
      direction: 'inbound',
      bandwidth: { sent: 0, received: 0 },
      duration: 1234,
      threat: null
    },
    // Auth server
    {
      id: 'conn_009',
      protocol: 'TCP',
      localAddress: '0.0.0.0',
      localPort: 8082,
      remoteAddress: '*',
      remotePort: 0,
      state: 'LISTENING',
      process: 'node.exe',
      pid: 13824,
      direction: 'inbound',
      bandwidth: { sent: 0, received: 0 },
      duration: 567,
      threat: null
    }
  ];

  return connections;
};

/**
 * Get geolocation for IP address
 */
const getGeoLocation = (ip) => {
  // Check for exact match
  if (GEO_DATABASE[ip]) {
    return GEO_DATABASE[ip];
  }

  // Check for prefix match
  for (const prefix in GEO_DATABASE) {
    if (ip.startsWith(prefix)) {
      return GEO_DATABASE[prefix];
    }
  }

  // Default for private IPs
  if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
    return { country: 'Local Network', city: 'LAN', org: 'Private Network', flag: '🏠' };
  }

  return { country: 'Unknown', city: 'Unknown', org: 'Unknown', flag: '🌍' };
};

/**
 * Check if IP is malicious
 */
const checkMaliciousIP = (ip) => {
  if (MALICIOUS_IPS.includes(ip)) {
    return { malicious: true, reason: 'Known malicious IP' };
  }
  if (C2_SERVERS.includes(ip)) {
    return { malicious: true, reason: 'Command & Control server' };
  }
  return { malicious: false };
};

/**
 * Check if port is suspicious
 */
const checkSuspiciousPort = (port, direction) => {
  if (direction === 'outbound' && SUSPICIOUS_PORTS.outbound.includes(port)) {
    return { suspicious: true, reason: 'Common backdoor/trojan port' };
  }
  if (direction === 'inbound' && SUSPICIOUS_PORTS.inbound.includes(port)) {
    return { suspicious: true, reason: 'Commonly exploited service port' };
  }
  return { suspicious: false };
};

/**
 * Scan for open ports on local machine
 */
export const scanOpenPorts = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const openPorts = [
        {
          port: 80,
          protocol: 'TCP',
          service: 'HTTP',
          state: 'LISTENING',
          process: 'httpd.exe',
          pid: 1234,
          risk: 'low',
          recommendation: 'Web server - ensure it\'s intentional'
        },
        {
          port: 443,
          protocol: 'TCP',
          service: 'HTTPS',
          state: 'LISTENING',
          process: 'httpd.exe',
          pid: 1234,
          risk: 'low',
          recommendation: 'Secure web server - normal'
        },
        {
          port: 3000,
          protocol: 'TCP',
          service: 'Node.js Dev Server',
          state: 'LISTENING',
          process: 'node.exe',
          pid: 5678,
          risk: 'low',
          recommendation: 'Development server - close when not in use'
        },
        {
          port: 8082,
          protocol: 'TCP',
          service: 'Auth Server',
          state: 'LISTENING',
          process: 'node.exe',
          pid: 5680,
          risk: 'low',
          recommendation: 'Backend service - normal'
        },
        {
          port: 135,
          protocol: 'TCP',
          service: 'RPC',
          state: 'LISTENING',
          process: 'svchost.exe',
          pid: 892,
          risk: 'medium',
          recommendation: 'Windows RPC - can be exploited, consider disabling if not needed'
        },
        {
          port: 445,
          protocol: 'TCP',
          service: 'SMB',
          state: 'LISTENING',
          process: 'System',
          pid: 4,
          risk: 'high',
          recommendation: 'File sharing - disable if not needed, frequently targeted by ransomware'
        },
        {
          port: 3389,
          protocol: 'TCP',
          service: 'RDP',
          state: 'LISTENING',
          process: 'svchost.exe',
          pid: 1024,
          risk: 'high',
          recommendation: 'Remote Desktop - use VPN or disable if not needed'
        },
        {
          port: 5900,
          protocol: 'TCP',
          service: 'VNC',
          state: 'LISTENING',
          process: 'vnc.exe',
          pid: 3456,
          risk: 'medium',
          recommendation: 'Remote access - ensure strong authentication'
        }
      ];

      resolve({
        success: true,
        ports: openPorts,
        summary: {
          total: openPorts.length,
          low: openPorts.filter(p => p.risk === 'low').length,
          medium: openPorts.filter(p => p.risk === 'medium').length,
          high: openPorts.filter(p => p.risk === 'high').length
        },
        scannedAt: new Date().toISOString()
      });
    }, 2000);
  });
};

/**
 * Get active network connections
 */
export const getActiveConnections = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const connections = generateActiveConnections();
      
      // Enrich with geo data and threat analysis
      const enriched = connections.map(conn => {
        const geo = getGeoLocation(conn.remoteAddress);
        const malicious = checkMaliciousIP(conn.remoteAddress);
        const portCheck = checkSuspiciousPort(
          conn.direction === 'outbound' ? conn.remotePort : conn.localPort,
          conn.direction
        );

        let threat = conn.threat;
        if (malicious.malicious && !threat) {
          threat = {
            level: 'critical',
            type: 'Malicious IP',
            description: malicious.reason
          };
        } else if (portCheck.suspicious && !threat) {
          threat = {
            level: 'medium',
            type: 'Suspicious Port',
            description: portCheck.reason
          };
        }

        return {
          ...conn,
          geo,
          threat
        };
      });

      const summary = {
        total: enriched.length,
        established: enriched.filter(c => c.state === 'ESTABLISHED').length,
        listening: enriched.filter(c => c.state === 'LISTENING').length,
        threats: enriched.filter(c => c.threat).length,
        inbound: enriched.filter(c => c.direction === 'inbound').length,
        outbound: enriched.filter(c => c.direction === 'outbound').length
      };

      resolve({
        success: true,
        connections: enriched,
        summary,
        timestamp: new Date().toISOString()
      });
    }, 1000);
  });
};

/**
 * Firewall rules database
 */
let firewallRules = [
  {
    id: 'rule_001',
    name: 'Block Tor Network',
    direction: 'outbound',
    action: 'block',
    protocol: 'TCP',
    ports: [9001, 9030, 9050, 9051],
    ips: MALICIOUS_IPS,
    enabled: true,
    priority: 1,
    description: 'Blocks connections to known Tor exit nodes'
  },
  {
    id: 'rule_002',
    name: 'Block Inbound RDP',
    direction: 'inbound',
    action: 'block',
    protocol: 'TCP',
    ports: [3389],
    ips: ['*'],
    enabled: false,
    priority: 2,
    description: 'Blocks all inbound Remote Desktop connections'
  },
  {
    id: 'rule_003',
    name: 'Allow Web Browsing',
    direction: 'outbound',
    action: 'allow',
    protocol: 'TCP',
    ports: [80, 443],
    ips: ['*'],
    enabled: true,
    priority: 10,
    description: 'Allows HTTP and HTTPS traffic'
  },
  {
    id: 'rule_004',
    name: 'Block SMB',
    direction: 'inbound',
    action: 'block',
    protocol: 'TCP',
    ports: [445, 139],
    ips: ['*'],
    enabled: true,
    priority: 1,
    description: 'Blocks inbound SMB to prevent ransomware spread'
  }
];

/**
 * Get firewall rules
 */
export const getFirewallRules = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        success: true,
        rules: firewallRules,
        summary: {
          total: firewallRules.length,
          enabled: firewallRules.filter(r => r.enabled).length,
          disabled: firewallRules.filter(r => !r.enabled).length,
          block: firewallRules.filter(r => r.action === 'block').length,
          allow: firewallRules.filter(r => r.action === 'allow').length
        }
      });
    }, 500);
  });
};

/**
 * Add firewall rule
 */
export const addFirewallRule = async (rule) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const newRule = {
        ...rule,
        id: `rule_${String(firewallRules.length + 1).padStart(3, '0')}`,
        enabled: true
      };
      firewallRules.push(newRule);
      
      resolve({
        success: true,
        rule: newRule,
        message: 'Firewall rule added successfully'
      });
    }, 300);
  });
};

/**
 * Update firewall rule
 */
export const updateFirewallRule = async (id, updates) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const index = firewallRules.findIndex(r => r.id === id);
      if (index !== -1) {
        firewallRules[index] = { ...firewallRules[index], ...updates };
        resolve({
          success: true,
          rule: firewallRules[index],
          message: 'Firewall rule updated successfully'
        });
      } else {
        resolve({
          success: false,
          message: 'Rule not found'
        });
      }
    }, 300);
  });
};

/**
 * Delete firewall rule
 */
export const deleteFirewallRule = async (id) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const index = firewallRules.findIndex(r => r.id === id);
      if (index !== -1) {
        firewallRules.splice(index, 1);
        resolve({
          success: true,
          message: 'Firewall rule deleted successfully'
        });
      } else {
        resolve({
          success: false,
          message: 'Rule not found'
        });
      }
    }, 300);
  });
};

/**
 * Security profiles
 */
export const applySecurityProfile = async (profileName) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      let newRules = [];
      
      switch (profileName) {
        case 'maximum':
          newRules = [
            { name: 'Block All Inbound', direction: 'inbound', action: 'block', protocol: 'TCP', ports: ['*'], ips: ['*'], priority: 1, description: 'Blocks all inbound connections' },
            { name: 'Allow Web', direction: 'outbound', action: 'allow', protocol: 'TCP', ports: [80, 443], ips: ['*'], priority: 10, description: 'Allows web browsing only' }
          ];
          break;
        case 'balanced':
          newRules = [
            { name: 'Block Suspicious Ports', direction: 'inbound', action: 'block', protocol: 'TCP', ports: [135, 139, 445, 3389], ips: ['*'], priority: 1, description: 'Blocks commonly exploited ports' },
            { name: 'Allow Standard Services', direction: 'outbound', action: 'allow', protocol: 'TCP', ports: [80, 443, 21, 22], ips: ['*'], priority: 10, description: 'Allows standard internet services' }
          ];
          break;
        case 'gaming':
          newRules = [
            { name: 'Allow Gaming Ports', direction: 'inbound', action: 'allow', protocol: 'UDP', ports: [3074, 3075, 27015, 27036], ips: ['*'], priority: 5, description: 'Allows common gaming ports' },
            { name: 'Allow All Outbound', direction: 'outbound', action: 'allow', protocol: 'TCP', ports: ['*'], ips: ['*'], priority: 10, description: 'Allows all outbound traffic' }
          ];
          break;
        default:
          newRules = firewallRules;
      }

      // Generate IDs
      firewallRules = newRules.map((rule, idx) => ({
        ...rule,
        id: `rule_${String(idx + 1).padStart(3, '0')}`,
        enabled: true
      }));

      resolve({
        success: true,
        profile: profileName,
        rules: firewallRules,
        message: `${profileName} security profile applied`
      });
    }, 500);
  });
};

/**
 * Block specific IP
 */
export const blockIP = async (ip, reason) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const newRule = {
        id: `rule_${String(firewallRules.length + 1).padStart(3, '0')}`,
        name: `Block ${ip}`,
        direction: 'both',
        action: 'block',
        protocol: 'TCP',
        ports: ['*'],
        ips: [ip],
        enabled: true,
        priority: 1,
        description: reason || 'Manually blocked IP'
      };
      
      firewallRules.unshift(newRule);
      
      resolve({
        success: true,
        rule: newRule,
        message: `IP ${ip} has been blocked`
      });
    }, 300);
  });
};

/**
 * Get network statistics
 */
export const getNetworkStats = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        success: true,
        stats: {
          totalTraffic: {
            sent: 1250000000, // 1.25 GB
            received: 3450000000, // 3.45 GB
            total: 4700000000 // 4.7 GB
          },
          packetsBlocked: 1247,
          threatsBlocked: 23,
          connectionsActive: 47,
          bandwidthUsage: {
            current: 2.4, // Mbps
            peak: 45.6,
            average: 12.3
          },
          topProcesses: [
            { name: 'chrome.exe', bandwidth: 1200000, percentage: 45 },
            { name: 'node.exe', bandwidth: 800000, percentage: 30 },
            { name: 'svchost.exe', bandwidth: 400000, percentage: 15 },
            { name: 'system', bandwidth: 267000, percentage: 10 }
          ]
        },
        timestamp: new Date().toISOString()
      });
    }, 500);
  });
};

export default {
  scanOpenPorts,
  getActiveConnections,
  getFirewallRules,
  addFirewallRule,
  updateFirewallRule,
  deleteFirewallRule,
  applySecurityProfile,
  blockIP,
  getNetworkStats
};
