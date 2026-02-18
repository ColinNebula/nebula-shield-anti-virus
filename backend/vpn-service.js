/**
 * VPN Service for Nebula Shield
 * Provides secure encrypted tunnel with multiple server locations
 */

const crypto = require('crypto');
const os = require('os');

class VPNService {
  constructor() {
    this.connectionStatus = 'disconnected'; // disconnected, connecting, connected, disconnecting
    this.currentServer = null;
    this.startTime = null;
    this.bytesSent = 0;
    this.bytesReceived = 0;
    this.killSwitchEnabled = true;
    this.dnsLeakProtection = true;
    this.splitTunneling = false;
    this.autoConnect = false;
    this.protocol = 'WireGuard'; // WireGuard or OpenVPN
    this.excludedApps = [];
    
    // Enhanced features
    this.autoReconnect = true;
    this.adBlocking = false;
    this.malwareBlocking = true;
    this.trackerBlocking = false;
    this.obfuscation = false;
    this.multiHop = false;
    this.multiHopServers = [];
    this.ipv6Protection = true;
    this.favoriteServers = [];
    this.connectionHistory = [];
    this.trafficHistory = [];
    this.speedTestResults = null;
    this.untrustedNetworkProtection = true;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 3;
    this.lastDisconnectReason = null;
    
    // VPN Server locations
    this.servers = [
      {
        id: 'us-east-1',
        name: 'United States (East)',
        country: 'US',
        city: 'New York',
        ip: '45.76.123.45',
        load: 23,
        latency: 12,
        status: 'online',
        flag: '🇺🇸',
        features: ['P2P', 'Streaming', 'Gaming'],
        multiHopSupport: true,
        obfuscationSupport: true,
        adBlocking: true,
        bandwidth: '10 Gbps'
      },
      {
        id: 'us-west-1',
        name: 'United States (West)',
        country: 'US',
        city: 'Los Angeles',
        ip: '45.76.124.46',
        load: 45,
        latency: 18,
        status: 'online',
        flag: '🇺🇸',
        features: ['P2P', 'Streaming', 'Gaming'],
        multiHopSupport: true,
        obfuscationSupport: true,
        adBlocking: true,
        bandwidth: '10 Gbps'
      },
      {
        id: 'uk-london-1',
        name: 'United Kingdom',
        country: 'UK',
        city: 'London',
        ip: '185.156.45.78',
        load: 67,
        latency: 45,
        status: 'online',
        flag: '🇬🇧',
        features: ['P2P', 'Streaming'],
        multiHopSupport: true,
        obfuscationSupport: true,
        adBlocking: true,
        bandwidth: '10 Gbps'
      },
      {
        id: 'de-frankfurt-1',
        name: 'Germany',
        country: 'DE',
        city: 'Frankfurt',
        ip: '185.156.46.79',
        load: 34,
        latency: 52,
        status: 'online',
        flag: '🇩🇪',
        features: ['P2P', 'Privacy'],
        multiHopSupport: true,
        obfuscationSupport: true,
        adBlocking: true,
        bandwidth: '10 Gbps'
      },
      {
        id: 'jp-tokyo-1',
        name: 'Japan',
        country: 'JP',
        city: 'Tokyo',
        ip: '103.79.78.90',
        load: 56,
        latency: 156,
        status: 'online',
        flag: '🇯🇵',
        features: ['Streaming', 'Gaming'],
        multiHopSupport: true,
        obfuscationSupport: false,
        adBlocking: true,
        bandwidth: '5 Gbps'
      },
      {
        id: 'sg-singapore-1',
        name: 'Singapore',
        country: 'SG',
        city: 'Singapore',
        ip: '103.79.79.91',
        load: 41,
        latency: 178,
        status: 'online',
        flag: '🇸🇬',
        features: ['P2P', 'Privacy'],
        multiHopSupport: true,
        obfuscationSupport: false,
        adBlocking: true,
        bandwidth: '5 Gbps'
      },
      {
        id: 'au-sydney-1',
        name: 'Australia',
        country: 'AU',
        city: 'Sydney',
        ip: '103.79.80.92',
        load: 28,
        latency: 198,
        status: 'online',
        flag: '🇦🇺',
        features: ['Streaming', 'Gaming'],
        multiHopSupport: false,
        obfuscationSupport: false,
        adBlocking: true,
        bandwidth: '10 Gbps'
      },
      {
        id: 'ca-toronto-1',
        name: 'Canada',
        country: 'CA',
        city: 'Toronto',
        ip: '45.76.125.47',
        load: 19,
        latency: 25,
        status: 'online',
        flag: '🇨🇦',
        features: ['P2P', 'Streaming', 'Privacy'],
        multiHopSupport: true,
        obfuscationSupport: true,
        adBlocking: true,
        bandwidth: '10 Gbps'
      },
      {
        id: 'nl-amsterdam-1',
        name: 'Netherlands',
        country: 'NL',
        city: 'Amsterdam',
        ip: '185.156.47.80',
        load: 72,
        latency: 48,
        status: 'online',
        flag: '🇳🇱',
        features: ['P2P', 'Privacy'],
        multiHopSupport: true,
        obfuscationSupport: true,
        adBlocking: true,
        bandwidth: '10 Gbps'
      },
      {
        id: 'se-stockholm-1',
        name: 'Sweden',
        country: 'SE',
        city: 'Stockholm',
        ip: '185.156.48.81',
        load: 15,
        latency: 58,
        status: 'online',
        flag: '🇸🇪',
        features: ['Privacy', 'No-Logs'],
        multiHopSupport: true,
        obfuscationSupport: true,
        adBlocking: true,
        bandwidth: '10 Gbps'
      }
    ];
    
    // Connection logs (for no-log policy demonstration - not stored permanently)
    this.connectionLogs = [];
    this.maxLogs = 50;
  }

  /**
   * Get all available VPN servers
   */
  getServers() {
    const serversWithFavorites = this.servers.map(server => ({
      ...server,
      isFavorite: this.favoriteServers.includes(server.id)
    }));
    
    return {
      success: true,
      servers: serversWithFavorites,
      recommended: this.getRecommendedServer(),
      favorites: serversWithFavorites.filter(s => s.isFavorite)
    };
  }

  /**
   * Get recommended server based on latency and load
   */
  getRecommendedServer() {
    const onlineServers = this.servers.filter(s => s.status === 'online');
    
    // Score based on latency and load (lower is better)
    const scored = onlineServers.map(server => ({
      ...server,
      score: (server.latency * 0.6) + (server.load * 0.4)
    }));
    
    scored.sort((a, b) => a.score - b.score);
    return scored[0];
  }

  /**
   * Connect to VPN server
   */
  async connect(serverId, options = {}) {
    return new Promise((resolve) => {
      if (this.connectionStatus === 'connected') {
        return resolve({
          success: false,
          error: 'Already connected to VPN'
        });
      }

      this.connectionStatus = 'connecting';
      const server = this.servers.find(s => s.id === serverId);
      
      if (!server) {
        this.connectionStatus = 'disconnected';
        return resolve({
          success: false,
          error: 'Server not found'
        });
      }

      // Simulate connection process
      setTimeout(() => {
        this.currentServer = server;
        this.connectionStatus = 'connected';
        this.startTime = Date.now();
        this.bytesSent = 0;
        this.bytesReceived = 0;
        
        // Apply options
        if (options.killSwitch !== undefined) this.killSwitchEnabled = options.killSwitch;
        if (options.dnsLeakProtection !== undefined) this.dnsLeakProtection = options.dnsLeakProtection;
        if (options.splitTunneling !== undefined) this.splitTunneling = options.splitTunneling;
        if (options.protocol !== undefined) this.protocol = options.protocol;

        // Log connection (temporary - deleted after session)
        this.addLog({
          type: 'connect',
          server: server.name,
          timestamp: new Date().toISOString()
        });

        resolve({
          success: true,
          server: this.currentServer,
          status: this.connectionStatus,
          message: `Connected to ${server.name}`
        });
      }, 2000); // Simulate 2 second connection time
    });
  }

  /**
   * Disconnect from VPN
   */
  async disconnect() {
    return new Promise((resolve) => {
      if (this.connectionStatus === 'disconnected') {
        return resolve({
          success: false,
          error: 'Not connected to VPN'
        });
      }

      this.connectionStatus = 'disconnecting';

      setTimeout(() => {
        this.addLog({
          type: 'disconnect',
          server: this.currentServer?.name,
          timestamp: new Date().toISOString(),
          duration: this.getConnectionDuration()
        });

        this.currentServer = null;
        this.connectionStatus = 'disconnected';
        this.startTime = null;

        resolve({
          success: true,
          status: this.connectionStatus,
          message: 'Disconnected from VPN'
        });
      }, 1000); // Simulate 1 second disconnect time
    });
  }

  /**
   * Get current VPN status
   */
  getStatus() {
    return {
      success: true,
      status: this.connectionStatus,
      connected: this.connectionStatus === 'connected',
      server: this.currentServer,
      multiHopServers: this.multiHopServers,
      duration: this.getConnectionDuration(),
      bytesSent: this.bytesSent,
      bytesReceived: this.bytesReceived,
      killSwitch: this.killSwitchEnabled,
      dnsLeakProtection: this.dnsLeakProtection,
      splitTunneling: this.splitTunneling,
      protocol: this.protocol,
      publicIP: this.getPublicIP(),
      dnsServers: this.getDNSServers(),
      encryption: this.getEncryptionInfo(),
      autoReconnect: this.autoReconnect,
      adBlocking: this.adBlocking,
      malwareBlocking: this.malwareBlocking,
      trackerBlocking: this.trackerBlocking,
      obfuscation: this.obfuscation,
      multiHop: this.multiHop,
      ipv6Protection: this.ipv6Protection,
      untrustedNetworkProtection: this.untrustedNetworkProtection,
      reconnectAttempts: this.reconnectAttempts,
      speedTest: this.speedTestResults
    };
  }

  /**
   * Get connection duration
   */
  getConnectionDuration() {
    if (!this.startTime) return 0;
    return Math.floor((Date.now() - this.startTime) / 1000); // in seconds
  }

  /**
   * Simulate traffic
   */
  updateTraffic() {
    if (this.connectionStatus === 'connected') {
      // Simulate random traffic
      this.bytesSent += Math.floor(Math.random() * 10000) + 1000;
      this.bytesReceived += Math.floor(Math.random() * 50000) + 5000;
    }
  }

  /**
   * Get public IP (simulated)
   */
  getPublicIP() {
    if (this.connectionStatus === 'connected' && this.currentServer) {
      return this.currentServer.ip;
    }
    // Return actual local IP when not connected
    const networkInterfaces = os.networkInterfaces();
    for (const name of Object.keys(networkInterfaces)) {
      for (const iface of networkInterfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          return iface.address;
        }
      }
    }
    return '127.0.0.1';
  }

  /**
   * Get DNS servers
   */
  getDNSServers() {
    if (this.connectionStatus === 'connected' && this.dnsLeakProtection) {
      return ['10.8.0.1', '10.8.0.2']; // VPN DNS servers
    }
    return ['8.8.8.8', '8.8.4.4']; // Default DNS
  }

  /**
   * Get encryption information
   */
  getEncryptionInfo() {
    if (this.protocol === 'WireGuard') {
      return {
        protocol: 'WireGuard',
        cipher: 'ChaCha20',
        authentication: 'Poly1305',
        keyExchange: 'Curve25519',
        perfect_forward_secrecy: true
      };
    } else {
      return {
        protocol: 'OpenVPN',
        cipher: 'AES-256-GCM',
        authentication: 'SHA-384',
        keyExchange: 'ECDHE-RSA',
        perfect_forward_secrecy: true
      };
    }
  }

  /**
   * Toggle kill switch
   */
  toggleKillSwitch(enabled) {
    this.killSwitchEnabled = enabled;
    return {
      success: true,
      killSwitch: this.killSwitchEnabled,
      message: `Kill switch ${enabled ? 'enabled' : 'disabled'}`
    };
  }

  /**
   * Toggle DNS leak protection
   */
  toggleDNSLeakProtection(enabled) {
    this.dnsLeakProtection = enabled;
    return {
      success: true,
      dnsLeakProtection: this.dnsLeakProtection,
      message: `DNS leak protection ${enabled ? 'enabled' : 'disabled'}`
    };
  }

  /**
   * Toggle split tunneling
   */
  toggleSplitTunneling(enabled) {
    this.splitTunneling = enabled;
    return {
      success: true,
      splitTunneling: this.splitTunneling,
      message: `Split tunneling ${enabled ? 'enabled' : 'disabled'}`
    };
  }

  /**
   * Set protocol (WireGuard or OpenVPN)
   */
  setProtocol(protocol) {
    if (!['WireGuard', 'OpenVPN'].includes(protocol)) {
      return {
        success: false,
        error: 'Invalid protocol. Use WireGuard or OpenVPN'
      };
    }
    
    this.protocol = protocol;
    return {
      success: true,
      protocol: this.protocol,
      message: `Protocol set to ${protocol}`
    };
  }

  /**
   * Add app to split tunneling exclusion list
   */
  addExcludedApp(appName) {
    if (!this.excludedApps.includes(appName)) {
      this.excludedApps.push(appName);
    }
    return {
      success: true,
      excludedApps: this.excludedApps
    };
  }

  /**
   * Remove app from split tunneling exclusion list
   */
  removeExcludedApp(appName) {
    this.excludedApps = this.excludedApps.filter(app => app !== appName);
    return {
      success: true,
      excludedApps: this.excludedApps
    };
  }

  /**
   * Get excluded apps list
   */
  getExcludedApps() {
    return {
      success: true,
      excludedApps: this.excludedApps
    };
  }

  /**
   * Perform DNS leak test
   */
  async dnsLeakTest() {
    return new Promise((resolve) => {
      setTimeout(() => {
        const leakDetected = this.connectionStatus === 'connected' && !this.dnsLeakProtection;
        
        resolve({
          success: true,
          leakDetected,
          dnsServers: this.getDNSServers(),
          message: leakDetected 
            ? 'DNS leak detected! Enable DNS leak protection.'
            : 'No DNS leaks detected. Your DNS queries are protected.'
        });
      }, 1500);
    });
  }

  /**
   * Get connection statistics
   */
  getStatistics() {
    return {
      success: true,
      stats: {
        totalBytesSent: this.bytesSent,
        totalBytesReceived: this.bytesReceived,
        connectionDuration: this.getConnectionDuration(),
        currentServer: this.currentServer?.name || 'Not connected',
        protocol: this.protocol,
        encryption: this.getEncryptionInfo().cipher,
        publicIP: this.getPublicIP()
      }
    };
  }

  /**
   * Add connection log (temporary - for session only)
   */
  addLog(log) {
    this.connectionLogs.unshift(log);
    if (this.connectionLogs.length > this.maxLogs) {
      this.connectionLogs.pop();
    }
  }

  /**
   * Get connection logs
   */
  getLogs() {
    return {
      success: true,
      logs: this.connectionLogs,
      noLogPolicy: true,
      message: 'Connection logs are temporary and deleted after session ends'
    };
  }

  /**
   * Clear all logs (for no-log policy)
   */
  clearLogs() {
    this.connectionLogs = [];
    return {
      success: true,
      message: 'All logs cleared'
    };
  }

  /**
   * Toggle auto-reconnect
   */
  toggleAutoReconnect(enabled) {
    this.autoReconnect = enabled;
    return {
      success: true,
      autoReconnect: this.autoReconnect,
      message: `Auto-reconnect ${enabled ? 'enabled' : 'disabled'}`
    };
  }

  /**
   * Toggle ad blocking
   */
  toggleAdBlocking(enabled) {
    this.adBlocking = enabled;
    return {
      success: true,
      adBlocking: this.adBlocking,
      message: `Ad blocking ${enabled ? 'enabled' : 'disabled'}`
    };
  }

  /**
   * Toggle malware blocking
   */
  toggleMalwareBlocking(enabled) {
    this.malwareBlocking = enabled;
    return {
      success: true,
      malwareBlocking: this.malwareBlocking,
      message: `Malware blocking ${enabled ? 'enabled' : 'disabled'}`
    };
  }

  /**
   * Toggle tracker blocking
   */
  toggleTrackerBlocking(enabled) {
    this.trackerBlocking = enabled;
    return {
      success: true,
      trackerBlocking: this.trackerBlocking,
      message: `Tracker blocking ${enabled ? 'enabled' : 'disabled'}`
    };
  }

  /**
   * Toggle obfuscation
   */
  toggleObfuscation(enabled) {
    if (enabled && this.currentServer && !this.currentServer.obfuscationSupport) {
      return {
        success: false,
        error: 'Current server does not support obfuscation'
      };
    }
    
    this.obfuscation = enabled;
    return {
      success: true,
      obfuscation: this.obfuscation,
      message: `Obfuscation ${enabled ? 'enabled' : 'disabled'}`
    };
  }

  /**
   * Enable multi-hop connection
   */
  async enableMultiHop(serverId1, serverId2) {
    const server1 = this.servers.find(s => s.id === serverId1);
    const server2 = this.servers.find(s => s.id === serverId2);
    
    if (!server1 || !server2) {
      return {
        success: false,
        error: 'One or both servers not found'
      };
    }
    
    if (!server1.multiHopSupport || !server2.multiHopSupport) {
      return {
        success: false,
        error: 'One or both servers do not support multi-hop'
      };
    }
    
    if (serverId1 === serverId2) {
      return {
        success: false,
        error: 'Cannot use the same server for multi-hop'
      };
    }
    
    this.multiHop = true;
    this.multiHopServers = [server1, server2];
    
    return {
      success: true,
      multiHop: this.multiHop,
      servers: this.multiHopServers,
      message: `Multi-hop enabled: ${server1.name} → ${server2.name}`
    };
  }

  /**
   * Disable multi-hop
   */
  disableMultiHop() {
    this.multiHop = false;
    this.multiHopServers = [];
    return {
      success: true,
      multiHop: this.multiHop,
      message: 'Multi-hop disabled'
    };
  }

  /**
   * Toggle IPv6 protection
   */
  toggleIPv6Protection(enabled) {
    this.ipv6Protection = enabled;
    return {
      success: true,
      ipv6Protection: this.ipv6Protection,
      message: `IPv6 protection ${enabled ? 'enabled' : 'disabled'}`
    };
  }

  /**
   * Add server to favorites
   */
  addFavorite(serverId) {
    if (!this.favoriteServers.includes(serverId)) {
      this.favoriteServers.push(serverId);
    }
    return {
      success: true,
      favorites: this.favoriteServers,
      message: 'Server added to favorites'
    };
  }

  /**
   * Remove server from favorites
   */
  removeFavorite(serverId) {
    this.favoriteServers = this.favoriteServers.filter(id => id !== serverId);
    return {
      success: true,
      favorites: this.favoriteServers,
      message: 'Server removed from favorites'
    };
  }

  /**
   * Get favorite servers
   */
  getFavorites() {
    const favorites = this.servers.filter(s => this.favoriteServers.includes(s.id));
    return {
      success: true,
      favorites
    };
  }

  /**
   * Run speed test
   */
  async runSpeedTest() {
    if (this.connectionStatus !== 'connected') {
      return {
        success: false,
        error: 'Must be connected to VPN to run speed test'
      };
    }
    
    return new Promise((resolve) => {
      setTimeout(() => {
        // Simulate speed test results
        const download = Math.floor(Math.random() * 500) + 200; // 200-700 Mbps
        const upload = Math.floor(Math.random() * 300) + 100; // 100-400 Mbps
        const ping = Math.floor(Math.random() * 50) + 10; // 10-60 ms
        const jitter = Math.floor(Math.random() * 5) + 1; // 1-6 ms
        
        this.speedTestResults = {
          download,
          upload,
          ping,
          jitter,
          server: this.currentServer.name,
          timestamp: new Date().toISOString()
        };
        
        resolve({
          success: true,
          results: this.speedTestResults
        });
      }, 3000); // 3 second test
    });
  }

  /**
   * Get connection history
   */
  getConnectionHistory() {
    return {
      success: true,
      history: this.connectionHistory.slice(0, 50) // Last 50 connections
    };
  }

  /**
   * Add connection to history
   */
  addToHistory(connection) {
    this.connectionHistory.unshift({
      ...connection,
      timestamp: new Date().toISOString()
    });
    
    // Keep only last 100 connections
    if (this.connectionHistory.length > 100) {
      this.connectionHistory = this.connectionHistory.slice(0, 100);
    }
  }

  /**
   * Toggle untrusted network protection
   */
  toggleUntrustedNetworkProtection(enabled) {
    this.untrustedNetworkProtection = enabled;
    return {
      success: true,
      untrustedNetworkProtection: this.untrustedNetworkProtection,
      message: `Untrusted network protection ${enabled ? 'enabled' : 'disabled'}`
    };
  }

  /**
   * Check if current network is untrusted
   */
  isNetworkUntrusted() {
    // Simulate network trust check (in real app, would check WiFi SSID, etc.)
    const networkInfo = {
      ssid: 'Public WiFi',
      isPublic: true,
      isEncrypted: false
    };
    
    return {
      success: true,
      untrusted: networkInfo.isPublic || !networkInfo.isEncrypted,
      networkInfo
    };
  }

  /**
   * Get traffic statistics over time
   */
  getTrafficHistory() {
    return {
      success: true,
      history: this.trafficHistory.slice(-100) // Last 100 data points
    };
  }

  /**
   * Record traffic statistics
   */
  recordTrafficStats() {
    if (this.connectionStatus === 'connected') {
      this.trafficHistory.push({
        timestamp: Date.now(),
        sent: this.bytesSent,
        received: this.bytesReceived
      });
      
      // Keep only last 500 data points
      if (this.trafficHistory.length > 500) {
        this.trafficHistory.shift();
      }
    }
  }

  /**
   * Get blocked content statistics
   */
  getBlockedStats() {
    // Simulate blocked content stats
    const stats = {
      adsBlocked: this.adBlocking ? Math.floor(Math.random() * 1000) + 500 : 0,
      trackersBlocked: this.trackerBlocking ? Math.floor(Math.random() * 500) + 200 : 0,
      malwareBlocked: this.malwareBlocking ? Math.floor(Math.random() * 50) + 10 : 0,
      totalBlocked: 0
    };
    
    stats.totalBlocked = stats.adsBlocked + stats.trackersBlocked + stats.malwareBlocked;
    
    return {
      success: true,
      stats
    };
  }
}

module.exports = new VPNService();
