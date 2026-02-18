/**
 * VPN Service
 * Secure VPN connection management with multiple protocols and servers
 */

import notificationService from './notificationService';

// VPN Server database
const VPN_SERVERS = {
  us: [
    { id: 'us-east-1', name: 'New York', country: 'United States', region: 'us-east', ip: '45.79.123.45', load: 23, latency: 12, protocol: ['OpenVPN', 'WireGuard', 'IKEv2'] },
    { id: 'us-west-1', name: 'Los Angeles', country: 'United States', region: 'us-west', ip: '173.255.234.12', load: 45, latency: 8, protocol: ['OpenVPN', 'WireGuard', 'IKEv2'] },
    { id: 'us-central-1', name: 'Chicago', country: 'United States', region: 'us-central', ip: '66.228.45.78', load: 67, latency: 15, protocol: ['OpenVPN', 'WireGuard'] }
  ],
  eu: [
    { id: 'eu-uk-1', name: 'London', country: 'United Kingdom', region: 'eu-west', ip: '185.107.56.23', load: 34, latency: 25, protocol: ['OpenVPN', 'WireGuard', 'IKEv2'] },
    { id: 'eu-de-1', name: 'Frankfurt', country: 'Germany', region: 'eu-central', ip: '138.199.23.45', load: 56, latency: 30, protocol: ['OpenVPN', 'WireGuard', 'IKEv2'] },
    { id: 'eu-fr-1', name: 'Paris', country: 'France', region: 'eu-west', ip: '195.154.67.89', load: 29, latency: 28, protocol: ['OpenVPN', 'WireGuard'] },
    { id: 'eu-nl-1', name: 'Amsterdam', country: 'Netherlands', region: 'eu-west', ip: '176.223.45.90', load: 41, latency: 27, protocol: ['OpenVPN', 'WireGuard', 'IKEv2'] }
  ],
  asia: [
    { id: 'asia-jp-1', name: 'Tokyo', country: 'Japan', region: 'asia-east', ip: '153.127.23.56', load: 78, latency: 120, protocol: ['OpenVPN', 'WireGuard'] },
    { id: 'asia-sg-1', name: 'Singapore', country: 'Singapore', region: 'asia-southeast', ip: '139.59.234.67', load: 52, latency: 140, protocol: ['OpenVPN', 'WireGuard', 'IKEv2'] },
    { id: 'asia-in-1', name: 'Mumbai', country: 'India', region: 'asia-south', ip: '165.232.123.45', load: 61, latency: 160, protocol: ['OpenVPN', 'WireGuard'] }
  ],
  oceania: [
    { id: 'oce-au-1', name: 'Sydney', country: 'Australia', region: 'oceania', ip: '139.99.45.78', load: 38, latency: 180, protocol: ['OpenVPN', 'WireGuard', 'IKEv2'] }
  ]
};

class VPNService {
  constructor() {
    this.connected = false;
    this.currentServer = null;
    this.protocol = 'WireGuard'; // Default protocol
    this.connectionStartTime = null;
    this.bytesTransferred = { sent: 0, received: 0 };
    this.connectionHistory = [];
    this.killSwitch = true; // Auto-disconnect if VPN drops
    this.autoReconnect = true;
    this.dnsLeakProtection = true;
    this.ipv6LeakProtection = true;
    this.splitTunneling = [];
    this.listeners = new Set();
    this.stats = {
      totalConnections: 0,
      totalDataTransferred: 0,
      averageLatency: 0,
      uptime: 0
    };
    this.loadSettings();
    this.startMonitoring();
  }

  // ==================== SERVER MANAGEMENT ====================

  getAllServers() {
    const allServers = [];
    Object.values(VPN_SERVERS).forEach(regionServers => {
      allServers.push(...regionServers);
    });
    return allServers;
  }

  getServersByRegion(region) {
    return VPN_SERVERS[region] || [];
  }

  getFastestServer() {
    const allServers = this.getAllServers();
    return allServers.reduce((fastest, server) => {
      const serverScore = server.latency + (server.load * 0.5);
      const fastestScore = fastest.latency + (fastest.load * 0.5);
      return serverScore < fastestScore ? server : fastest;
    });
  }

  getRecommendedServer(preferences = {}) {
    const { region, protocol, maxLatency = 100, maxLoad = 80 } = preferences;
    
    let servers = this.getAllServers();
    
    if (region) {
      servers = this.getServersByRegion(region);
    }
    
    if (protocol) {
      servers = servers.filter(s => s.protocol.includes(protocol));
    }
    
    servers = servers.filter(s => s.latency <= maxLatency && s.load <= maxLoad);
    
    if (servers.length === 0) return this.getFastestServer();
    
    return servers.reduce((best, server) => {
      const serverScore = server.latency + (server.load * 0.3);
      const bestScore = best.latency + (best.load * 0.3);
      return serverScore < bestScore ? server : best;
    });
  }

  // ==================== CONNECTION MANAGEMENT ====================

  async connect(serverId = null, protocol = null) {
    if (this.connected) {
      throw new Error('Already connected to VPN. Disconnect first.');
    }

    try {
      // Get server
      const server = serverId 
        ? this.getAllServers().find(s => s.id === serverId)
        : this.getFastestServer();

      if (!server) {
        throw new Error('Server not found');
      }

      // Set protocol
      this.protocol = protocol || this.protocol;
      if (!server.protocol.includes(this.protocol)) {
        this.protocol = server.protocol[0]; // Fallback to first available
      }

      // Simulate connection process
      this.notifyListeners({ type: 'connecting', server, protocol: this.protocol });

      // Apply DNS leak protection
      if (this.dnsLeakProtection) {
        await this.configureDNS(server);
      }

      // Apply IPv6 leak protection
      if (this.ipv6LeakProtection) {
        await this.disableIPv6();
      }

      // Establish VPN tunnel
      await this.establishTunnel(server, this.protocol);

      // Connection successful
      this.connected = true;
      this.currentServer = server;
      this.connectionStartTime = Date.now();
      this.bytesTransferred = { sent: 0, received: 0 };

      // Add to history
      this.connectionHistory.unshift({
        serverId: server.id,
        serverName: server.name,
        country: server.country,
        protocol: this.protocol,
        connectedAt: new Date().toISOString(),
        disconnectedAt: null,
        duration: null,
        dataTransferred: null
      });

      // Update stats
      this.stats.totalConnections++;
      this.saveSettings();

      this.notifyListeners({ 
        type: 'connected', 
        server, 
        protocol: this.protocol,
        publicIp: server.ip 
      });

      notificationService.show({
        type: 'success',
        title: 'VPN Connected',
        message: `Connected to ${server.name} via ${this.protocol}`,
        duration: 3000
      });

      return {
        success: true,
        server,
        protocol: this.protocol,
        publicIp: server.ip
      };

    } catch (error) {
      this.notifyListeners({ type: 'error', error: error.message });
      throw error;
    }
  }

  async disconnect() {
    if (!this.connected) {
      throw new Error('Not connected to VPN');
    }

    try {
      this.notifyListeners({ type: 'disconnecting' });

      // Close VPN tunnel
      await this.closeTunnel();

      // Restore DNS
      if (this.dnsLeakProtection) {
        await this.restoreDNS();
      }

      // Re-enable IPv6
      if (this.ipv6LeakProtection) {
        await this.enableIPv6();
      }

      // Update history
      const currentConnection = this.connectionHistory[0];
      if (currentConnection && !currentConnection.disconnectedAt) {
        currentConnection.disconnectedAt = new Date().toISOString();
        currentConnection.duration = Date.now() - this.connectionStartTime;
        currentConnection.dataTransferred = this.bytesTransferred.sent + this.bytesTransferred.received;
      }

      // Update stats
      this.stats.totalDataTransferred += this.bytesTransferred.sent + this.bytesTransferred.received;
      this.stats.uptime += Date.now() - this.connectionStartTime;

      const serverName = this.currentServer.name;
      
      // Reset connection state
      this.connected = false;
      this.currentServer = null;
      this.connectionStartTime = null;

      this.saveSettings();
      this.notifyListeners({ type: 'disconnected' });

      notificationService.show({
        type: 'info',
        title: 'VPN Disconnected',
        message: `Disconnected from ${serverName}`,
        duration: 3000
      });

      return { success: true };

    } catch (error) {
      this.notifyListeners({ type: 'error', error: error.message });
      throw error;
    }
  }

  async reconnect() {
    if (!this.currentServer) {
      throw new Error('No previous connection to reconnect');
    }

    await this.disconnect();
    await this.connect(this.currentServer.id, this.protocol);
  }

  // ==================== PROTOCOL IMPLEMENTATION ====================

  async establishTunnel(server, protocol) {
    return new Promise((resolve) => {
      // Simulate tunnel establishment
      setTimeout(() => {
        console.log(`[VPN] Establishing ${protocol} tunnel to ${server.name}...`);
        resolve();
      }, 2000);
    });
  }

  async closeTunnel() {
    return new Promise((resolve) => {
      setTimeout(() => {
        console.log('[VPN] Closing tunnel...');
        resolve();
      }, 1000);
    });
  }

  async configureDNS(server) {
    return new Promise((resolve) => {
      setTimeout(() => {
        console.log(`[VPN] Configuring DNS to ${server.ip}...`);
        resolve();
      }, 500);
    });
  }

  async restoreDNS() {
    return new Promise((resolve) => {
      setTimeout(() => {
        console.log('[VPN] Restoring original DNS...');
        resolve();
      }, 500);
    });
  }

  async disableIPv6() {
    return new Promise((resolve) => {
      setTimeout(() => {
        console.log('[VPN] Disabling IPv6 for leak protection...');
        resolve();
      }, 300);
    });
  }

  async enableIPv6() {
    return new Promise((resolve) => {
      setTimeout(() => {
        console.log('[VPN] Re-enabling IPv6...');
        resolve();
      }, 300);
    });
  }

  // ==================== FEATURES ====================

  setProtocol(protocol) {
    if (this.connected) {
      throw new Error('Cannot change protocol while connected');
    }
    this.protocol = protocol;
    this.saveSettings();
  }

  toggleKillSwitch(enabled) {
    this.killSwitch = enabled;
    this.saveSettings();
    this.notifyListeners({ type: 'settings_changed', setting: 'killSwitch', value: enabled });
  }

  toggleAutoReconnect(enabled) {
    this.autoReconnect = enabled;
    this.saveSettings();
    this.notifyListeners({ type: 'settings_changed', setting: 'autoReconnect', value: enabled });
  }

  toggleDNSLeakProtection(enabled) {
    this.dnsLeakProtection = enabled;
    this.saveSettings();
    this.notifyListeners({ type: 'settings_changed', setting: 'dnsLeakProtection', value: enabled });
  }

  toggleIPv6LeakProtection(enabled) {
    this.ipv6LeakProtection = enabled;
    this.saveSettings();
    this.notifyListeners({ type: 'settings_changed', setting: 'ipv6LeakProtection', value: enabled });
  }

  addSplitTunnelApp(appName) {
    if (!this.splitTunneling.includes(appName)) {
      this.splitTunneling.push(appName);
      this.saveSettings();
      this.notifyListeners({ type: 'split_tunnel_updated', apps: this.splitTunneling });
    }
  }

  removeSplitTunnelApp(appName) {
    this.splitTunneling = this.splitTunneling.filter(app => app !== appName);
    this.saveSettings();
    this.notifyListeners({ type: 'split_tunnel_updated', apps: this.splitTunneling });
  }

  // ==================== MONITORING ====================

  startMonitoring() {
    setInterval(() => {
      if (this.connected) {
        // Simulate data transfer
        this.bytesTransferred.sent += Math.floor(Math.random() * 500000);
        this.bytesTransferred.received += Math.floor(Math.random() * 1500000);
        
        this.notifyListeners({
          type: 'stats_update',
          stats: this.getConnectionStats()
        });
      }
    }, 1000);

    // Check connection health
    setInterval(() => {
      if (this.connected) {
        this.checkConnectionHealth();
      }
    }, 5000);
  }

  async checkConnectionHealth() {
    // Simulate connection health check
    const healthy = Math.random() > 0.05; // 95% success rate

    if (!healthy && this.killSwitch) {
      console.warn('[VPN] Connection unhealthy - Kill switch activated');
      this.notifyListeners({ 
        type: 'kill_switch_activated',
        reason: 'Connection lost'
      });
      
      if (this.autoReconnect) {
        try {
          await this.reconnect();
        } catch (error) {
          console.error('[VPN] Auto-reconnect failed:', error);
        }
      }
    }
  }

  getConnectionStats() {
    if (!this.connected) {
      return null;
    }

    const duration = Date.now() - this.connectionStartTime;
    const uploadSpeed = (this.bytesTransferred.sent / (duration / 1000)).toFixed(2);
    const downloadSpeed = (this.bytesTransferred.received / (duration / 1000)).toFixed(2);

    return {
      server: this.currentServer,
      protocol: this.protocol,
      connected: true,
      duration,
      bytesTransferred: this.bytesTransferred,
      uploadSpeed: parseFloat(uploadSpeed),
      downloadSpeed: parseFloat(downloadSpeed),
      latency: this.currentServer.latency
    };
  }

  // ==================== LEAK TESTS ====================

  async testDNSLeak() {
    return new Promise((resolve) => {
      setTimeout(() => {
        const leaked = Math.random() < 0.05; // 5% chance of leak in simulation
        resolve({
          leaked,
          dnsServers: leaked 
            ? ['8.8.8.8', '8.8.4.4'] // Google DNS (leak)
            : [this.currentServer?.ip || '10.0.0.1'], // VPN DNS
          message: leaked 
            ? 'DNS leak detected! Your DNS requests are not protected.'
            : 'No DNS leak detected. Your DNS is secure.'
        });
      }, 2000);
    });
  }

  async testIPLeak() {
    return new Promise((resolve) => {
      setTimeout(() => {
        const leaked = Math.random() < 0.03; // 3% chance of leak
        resolve({
          leaked,
          detectedIP: leaked 
            ? '203.0.113.45' // Real IP (leak)
            : this.currentServer?.ip, // VPN IP
          expectedIP: this.currentServer?.ip,
          message: leaked 
            ? 'IP leak detected! Your real IP is exposed.'
            : 'No IP leak detected. Your IP is hidden.'
        });
      }, 1500);
    });
  }

  async testWebRTCLeak() {
    return new Promise((resolve) => {
      setTimeout(() => {
        const leaked = Math.random() < 0.1; // 10% chance
        resolve({
          leaked,
          message: leaked 
            ? 'WebRTC leak detected! Your local IP may be exposed.'
            : 'No WebRTC leak detected. WebRTC is secure.',
          localIPs: leaked ? ['192.168.1.100'] : []
        });
      }, 1000);
    });
  }

  async runFullLeakTest() {
    const [dnsTest, ipTest, webRTCTest] = await Promise.all([
      this.testDNSLeak(),
      this.testIPLeak(),
      this.testWebRTCLeak()
    ]);

    const allPassed = !dnsTest.leaked && !ipTest.leaked && !webRTCTest.leaked;

    return {
      passed: allPassed,
      dns: dnsTest,
      ip: ipTest,
      webRTC: webRTCTest,
      overall: allPassed 
        ? 'All tests passed! Your connection is secure.'
        : 'Security issues detected. Please review the results.'
    };
  }

  // ==================== UTILITIES ====================

  getStatus() {
    return {
      connected: this.connected,
      server: this.currentServer,
      protocol: this.protocol,
      killSwitch: this.killSwitch,
      autoReconnect: this.autoReconnect,
      dnsLeakProtection: this.dnsLeakProtection,
      ipv6LeakProtection: this.ipv6LeakProtection,
      splitTunneling: this.splitTunneling,
      stats: this.connected ? this.getConnectionStats() : null
    };
  }

  getConnectionHistory(limit = 10) {
    return this.connectionHistory.slice(0, limit);
  }

  getStatistics() {
    return {
      ...this.stats,
      currentConnection: this.connected ? this.getConnectionStats() : null
    };
  }

  // ==================== PERSISTENCE ====================

  loadSettings() {
    try {
      const saved = localStorage.getItem('vpn_settings');
      if (saved) {
        const settings = JSON.parse(saved);
        this.protocol = settings.protocol || 'WireGuard';
        this.killSwitch = settings.killSwitch !== undefined ? settings.killSwitch : true;
        this.autoReconnect = settings.autoReconnect !== undefined ? settings.autoReconnect : true;
        this.dnsLeakProtection = settings.dnsLeakProtection !== undefined ? settings.dnsLeakProtection : true;
        this.ipv6LeakProtection = settings.ipv6LeakProtection !== undefined ? settings.ipv6LeakProtection : true;
        this.splitTunneling = settings.splitTunneling || [];
      }

      const savedStats = localStorage.getItem('vpn_stats');
      if (savedStats) {
        this.stats = JSON.parse(savedStats);
      }

      const savedHistory = localStorage.getItem('vpn_history');
      if (savedHistory) {
        this.connectionHistory = JSON.parse(savedHistory);
      }
    } catch (error) {
      console.error('[VPN] Failed to load settings:', error);
    }
  }

  saveSettings() {
    try {
      localStorage.setItem('vpn_settings', JSON.stringify({
        protocol: this.protocol,
        killSwitch: this.killSwitch,
        autoReconnect: this.autoReconnect,
        dnsLeakProtection: this.dnsLeakProtection,
        ipv6LeakProtection: this.ipv6LeakProtection,
        splitTunneling: this.splitTunneling
      }));

      localStorage.setItem('vpn_stats', JSON.stringify(this.stats));
      localStorage.setItem('vpn_history', JSON.stringify(this.connectionHistory.slice(0, 50)));
    } catch (error) {
      console.error('[VPN] Failed to save settings:', error);
    }
  }

  // ==================== EVENT LISTENERS ====================

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  notifyListeners(event) {
    this.listeners.forEach(listener => {
      try {
        listener(event);
      } catch (error) {
        console.error('[VPN] Listener error:', error);
      }
    });
  }

  // ==================== CLEANUP ====================

  async cleanup() {
    if (this.connected) {
      await this.disconnect();
    }
    this.listeners.clear();
  }
}

// Export singleton instance
const vpnService = new VPNService();
export default vpnService;
