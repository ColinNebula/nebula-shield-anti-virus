/**
 * VPN Service for Nebula Shield Mobile
 * Secure VPN connection management
 */

import ApiService from './ApiService';

export interface VPNServer {
  id: string;
  name: string;
  country: string;
  city: string;
  ip: string;
  load: number;
  latency: number;
  status: 'online' | 'offline' | 'maintenance';
  flag: string;
  features: string[];
  multiHopSupport?: boolean;
  obfuscationSupport?: boolean;
  adBlocking?: boolean;
  bandwidth?: string;
  isFavorite?: boolean;
}

export interface VPNStatus {
  status: 'disconnected' | 'connecting' | 'connected' | 'disconnecting';
  connected: boolean;
  server: VPNServer | null;
  multiHopServers?: VPNServer[];
  duration: number;
  bytesSent: number;
  bytesReceived: number;
  killSwitch: boolean;
  dnsLeakProtection: boolean;
  splitTunneling: boolean;
  protocol: 'WireGuard' | 'OpenVPN';
  publicIP: string;
  dnsServers: string[];
  encryption: {
    protocol: string;
    cipher: string;
    authentication: string;
    keyExchange: string;
    perfect_forward_secrecy: boolean;
  };
  autoReconnect?: boolean;
  adBlocking?: boolean;
  malwareBlocking?: boolean;
  trackerBlocking?: boolean;
  obfuscation?: boolean;
  multiHop?: boolean;
  ipv6Protection?: boolean;
  untrustedNetworkProtection?: boolean;
  reconnectAttempts?: number;
  speedTest?: SpeedTestResult;
}

export interface SpeedTestResult {
  download: number;
  upload: number;
  ping: number;
  jitter: number;
  server: string;
  timestamp: string;
}

export interface BlockedStats {
  adsBlocked: number;
  trackersBlocked: number;
  malwareBlocked: number;
  totalBlocked: number;
}

export interface VPNConnectionOptions {
  killSwitch?: boolean;
  dnsLeakProtection?: boolean;
  splitTunneling?: boolean;
  protocol?: 'WireGuard' | 'OpenVPN';
}

class VPNService {
  /**
   * Get available VPN servers
   */
  async getServers() {
    try {
      const response = await ApiService.client.get('/vpn/servers');
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('Get VPN servers error:', error);
      return { success: false, error: error.message || 'Failed to get VPN servers' };
    }
  }

  /**
   * Connect to VPN server
   */
  async connect(serverId: string, options?: VPNConnectionOptions) {
    try {
      const response = await ApiService.client.post('/vpn/connect', {
        serverId,
        options
      });
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('VPN connect error:', error);
      return { success: false, error: error.message || 'Failed to connect to VPN' };
    }
  }

  /**
   * Disconnect from VPN
   */
  async disconnect() {
    try {
      const response = await ApiService.client.post('/vpn/disconnect');
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('VPN disconnect error:', error);
      return { success: false, error: error.message || 'Failed to disconnect from VPN' };
    }
  }

  /**
   * Get current VPN status
   */
  async getStatus(): Promise<{ success: boolean; data?: VPNStatus; error?: string }> {
    try {
      const response = await ApiService.client.get('/vpn/status');
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('Get VPN status error:', error);
      return { success: false, error: error.message || 'Failed to get VPN status' };
    }
  }

  /**
   * Toggle kill switch
   */
  async toggleKillSwitch(enabled: boolean) {
    try {
      const response = await ApiService.client.post('/vpn/killswitch', { enabled });
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('Toggle kill switch error:', error);
      return { success: false, error: error.message || 'Failed to toggle kill switch' };
    }
  }

  /**
   * Toggle DNS leak protection
   */
  async toggleDNSLeakProtection(enabled: boolean) {
    try {
      const response = await ApiService.client.post('/vpn/dns-protection', { enabled });
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('Toggle DNS protection error:', error);
      return { success: false, error: error.message || 'Failed to toggle DNS protection' };
    }
  }

  /**
   * Toggle split tunneling
   */
  async toggleSplitTunneling(enabled: boolean) {
    try {
      const response = await ApiService.client.post('/vpn/split-tunneling', { enabled });
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('Toggle split tunneling error:', error);
      return { success: false, error: error.message || 'Failed to toggle split tunneling' };
    }
  }

  /**
   * Set VPN protocol
   */
  async setProtocol(protocol: 'WireGuard' | 'OpenVPN') {
    try {
      const response = await ApiService.client.post('/vpn/protocol', { protocol });
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('Set protocol error:', error);
      return { success: false, error: error.message || 'Failed to set protocol' };
    }
  }

  /**
   * Perform DNS leak test
   */
  async dnsLeakTest() {
    try {
      const response = await ApiService.client.get('/vpn/dns-leak-test');
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('DNS leak test error:', error);
      return { success: false, error: error.message || 'Failed to perform DNS leak test' };
    }
  }

  /**
   * Get VPN statistics
   */
  async getStatistics() {
    try {
      const response = await ApiService.client.get('/vpn/statistics');
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('Get VPN statistics error:', error);
      return { success: false, error: error.message || 'Failed to get VPN statistics' };
    }
  }

  /**
   * Format bytes to human readable
   */
  formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  /**
   * Format duration to human readable
   */
  formatDuration(seconds: number): string {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${minutes}m`;
  }

  /**
   * Toggle auto-reconnect
   */
  async toggleAutoReconnect(enabled: boolean) {
    try {
      const response = await ApiService.client.post('/vpn/auto-reconnect', { enabled });
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Toggle ad blocking
   */
  async toggleAdBlocking(enabled: boolean) {
    try {
      const response = await ApiService.client.post('/vpn/ad-blocking', { enabled });
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Toggle malware blocking
   */
  async toggleMalwareBlocking(enabled: boolean) {
    try {
      const response = await ApiService.client.post('/vpn/malware-blocking', { enabled });
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Toggle tracker blocking
   */
  async toggleTrackerBlocking(enabled: boolean) {
    try {
      const response = await ApiService.client.post('/vpn/tracker-blocking', { enabled });
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Toggle obfuscation
   */
  async toggleObfuscation(enabled: boolean) {
    try {
      const response = await ApiService.client.post('/vpn/obfuscation', { enabled });
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Enable multi-hop connection
   */
  async enableMultiHop(serverId1: string, serverId2: string) {
    try {
      const response = await ApiService.client.post('/vpn/multi-hop/enable', { serverId1, serverId2 });
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Disable multi-hop
   */
  async disableMultiHop() {
    try {
      const response = await ApiService.client.post('/vpn/multi-hop/disable');
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Toggle IPv6 protection
   */
  async toggleIPv6Protection(enabled: boolean) {
    try {
      const response = await ApiService.client.post('/vpn/ipv6-protection', { enabled });
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Add server to favorites
   */
  async addFavorite(serverId: string) {
    try {
      const response = await ApiService.client.post('/vpn/favorites/add', { serverId });
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Remove server from favorites
   */
  async removeFavorite(serverId: string) {
    try {
      const response = await ApiService.client.post('/vpn/favorites/remove', { serverId });
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Get favorite servers
   */
  async getFavorites() {
    try {
      const response = await ApiService.client.get('/vpn/favorites');
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Run speed test
   */
  async runSpeedTest() {
    try {
      const response = await ApiService.client.post('/vpn/speed-test');
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Get connection history
   */
  async getConnectionHistory() {
    try {
      const response = await ApiService.client.get('/vpn/history');
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Toggle untrusted network protection
   */
  async toggleUntrustedNetworkProtection(enabled: boolean) {
    try {
      const response = await ApiService.client.post('/vpn/untrusted-network-protection', { enabled });
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Check if current network is untrusted
   */
  async checkNetworkTrust() {
    try {
      const response = await ApiService.client.get('/vpn/network-check');
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Get traffic history
   */
  async getTrafficHistory() {
    try {
      const response = await ApiService.client.get('/vpn/traffic-history');
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Get blocked content statistics
   */
  async getBlockedStats(): Promise<{ success: boolean; data?: { stats: BlockedStats }; error?: string }> {
    try {
      const response = await ApiService.client.get('/vpn/blocked-stats');
      return { success: true, data: response.data };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  }
}

export default new VPNService();
