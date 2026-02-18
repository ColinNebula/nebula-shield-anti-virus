/**
 * Network Traffic Monitor Service
 * Real-time monitoring of network connections and suspicious activity
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import ApiService from './ApiService';

export interface NetworkConnection {
  id: string;
  app: string;
  appIcon: string;
  protocol: 'TCP' | 'UDP' | 'HTTP' | 'HTTPS';
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  remoteHost: string;
  country: string;
  countryCode: string;
  state: 'ESTABLISHED' | 'LISTENING' | 'TIME_WAIT' | 'CLOSE_WAIT' | 'SYN_SENT';
  bytesIn: number;
  bytesOut: number;
  packetsIn: number;
  packetsOut: number;
  duration: number;
  isSuspicious: boolean;
  threatLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  reason?: string;
  timestamp: string;
}

export interface TrafficStats {
  totalConnections: number;
  activeConnections: number;
  suspiciousConnections: number;
  blockedConnections: number;
  totalBytesIn: number;
  totalBytesOut: number;
  topApps: Array<{
    app: string;
    connections: number;
    bytesIn: number;
    bytesOut: number;
  }>;
  topCountries: Array<{
    country: string;
    code: string;
    connections: number;
  }>;
  protocolDistribution: {
    tcp: number;
    udp: number;
    http: number;
    https: number;
  };
}

export interface SuspiciousActivity {
  id: string;
  type: 'malware_c2' | 'data_exfiltration' | 'port_scan' | 'ddos' | 'suspicious_domain' | 'unusual_traffic';
  severity: 'low' | 'medium' | 'high' | 'critical';
  app: string;
  destination: string;
  description: string;
  recommendation: string;
  timestamp: string;
  blocked: boolean;
}

export interface TrafficHistory {
  timestamp: string;
  bytesIn: number;
  bytesOut: number;
  connections: number;
  threats: number;
}

export interface AppTrafficData {
  app: string;
  appIcon: string;
  packageName: string;
  totalBytesIn: number;
  totalBytesOut: number;
  connections: number;
  suspiciousConnections: number;
  blockedConnections: number;
  trackers: string[];
  ads: string[];
  isBlocked: boolean;
  lastActive: string;
}

export interface FirewallRule {
  id: string;
  app: string;
  packageName: string;
  type: 'block_all' | 'block_wifi' | 'block_cellular' | 'allow_vpn_only' | 'custom';
  enabled: boolean;
  createdAt: string;
}

export interface BlockedTracker {
  domain: string;
  category: 'analytics' | 'advertising' | 'social' | 'location' | 'fingerprinting';
  blockedCount: number;
  apps: string[];
  lastSeen: string;
}

interface TrackerBlockStats {
  [domain: string]: {
    blockedCount: number;
    apps: Set<string>;
    lastSeen: string;
  };
}

export interface SuspiciousServer {
  ip: string;
  domain: string;
  country: string;
  countryCode: string;
  reason: 'malware' | 'phishing' | 'spam' | 'botnet' | 'tor' | 'vpn' | 'unknown';
  threatScore: number;
  apps: string[];
  connections: number;
  isBlocked: boolean;
}

class NetworkTrafficServiceClass {
  private static readonly TRACKER_STATS_KEY = 'nebula_tracker_block_stats';
  private updateInterval: NodeJS.Timeout | null = null;
  private blockedApps: Set<string> = new Set();
  private blockedDomains: Set<string> = new Set([
    // Ad networks
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'facebook.com/tr', 'graph.facebook.com', 'ads.twitter.com',
    // Analytics
    'google-analytics.com', 'analytics.google.com', 'mixpanel.com',
    'segment.com', 'amplitude.com', 'adjust.com',
    // Trackers
    'scorecardresearch.com', 'quantserve.com', 'moatads.com',
    'krxd.net', 'adsrvr.org', 'adnxs.com',
  ]);
  private suspiciousIPs: Set<string> = new Set([
    '185.220.101.34', '45.33.32.156', '178.73.215.171',
  ]);
  private trackerStats: TrackerBlockStats = {};
  private initialized: boolean = false;

  /**
   * Initialize the service and load saved stats
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;
    
    await this.loadTrackerStats();
    this.initialized = true;
  }
  private async loadTrackerStats(): Promise<void> {
    try {
      const stored = await AsyncStorage.getItem(NetworkTrafficServiceClass.TRACKER_STATS_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        // Reconstruct Sets from arrays
        this.trackerStats = {};
        for (const [domain, stats] of Object.entries(parsed)) {
          this.trackerStats[domain] = {
            ...(stats as any),
            apps: new Set<string>((stats as any).apps || []),
          };
        }
      }
    } catch (error) {
      console.error('Failed to load tracker stats:', error);
      this.trackerStats = {};
    }
  }

  /**
   * Save tracker block stats to AsyncStorage
   */
  private async saveTrackerStats(): Promise<void> {
    try {
      // Convert Sets to arrays for JSON serialization
      const serializable: any = {};
      for (const [domain, stats] of Object.entries(this.trackerStats)) {
        serializable[domain] = {
          blockedCount: stats.blockedCount,
          apps: Array.from(stats.apps),
          lastSeen: stats.lastSeen,
        };
      }
      await AsyncStorage.setItem(
        NetworkTrafficServiceClass.TRACKER_STATS_KEY,
        JSON.stringify(serializable)
      );
    } catch (error) {
      console.error('Failed to save tracker stats:', error);
    }
  }

  /**
   * Record a blocked tracker
   */
  async recordBlockedTracker(domain: string, app: string): Promise<void> {
    if (!this.trackerStats[domain]) {
      this.trackerStats[domain] = {
        blockedCount: 0,
        apps: new Set(),
        lastSeen: new Date().toISOString(),
      };
    }

    this.trackerStats[domain].blockedCount++;
    this.trackerStats[domain].apps.add(app);
    this.trackerStats[domain].lastSeen = new Date().toISOString();

    // Save to storage
    await this.saveTrackerStats();
  }

  /**
   * Check if a domain should be blocked
   */
  shouldBlockDomain(domain: string): boolean {
    // Check exact match
    if (this.blockedDomains.has(domain)) {
      return true;
    }

    // Check if any blocked domain is a substring of the requested domain
    for (const blockedDomain of this.blockedDomains) {
      if (domain.includes(blockedDomain)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get current network connections
   */
  async getActiveConnections(): Promise<NetworkConnection[]> {
    await this.initialize();
    
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.getActiveConnections();
    //   if (result.success) {
    //     return result.data;
    //   }
    // } catch (error) {
    //   console.error('Get connections error:', error);
    // }

    // Use mock connections
    return await this.generateMockConnections();
  }

  /**
   * Get network traffic statistics
   */
  async getTrafficStats(): Promise<TrafficStats> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.getTrafficStats();
    //   if (result.success) {
    //     return result.data;
    //   }
    // } catch (error) {
    //   console.error('Get stats error:', error);
    // }

    // Use mock stats
    return this.generateMockStats();
  }

  /**
   * Get suspicious activities
   */
  async getSuspiciousActivities(): Promise<SuspiciousActivity[]> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.getSuspiciousActivities();
    //   if (result.success) {
    //     return result.data;
    //   }
    // } catch (error) {
    //   console.error('Get suspicious activities error:', error);
    // }

    // Use mock suspicious activities
    return this.generateMockSuspiciousActivities();
  }

  /**
   * Get traffic history for charts
   */
  async getTrafficHistory(hours: number = 24): Promise<TrafficHistory[]> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.getTrafficHistory(hours);
    //   if (result.success) {
    //     return result.data;
    //   }
    // } catch (error) {
    //   console.error('Get traffic history error:', error);
    // }

    // Use mock history
    return this.generateMockHistory(hours);
  }

  /**
   * Block a connection
   */
  async blockConnection(connectionId: string): Promise<boolean> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.blockConnection(connectionId);
    //   return result.success || false;
    // } catch (error) {
    //   console.error('Block connection error:', error);
    //   return false;
    // }
    return true;
  }

  /**
   * Block an app from network access
   */
  async blockApp(appName: string): Promise<boolean> {
    this.blockedApps.add(appName);
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.blockApp(appName);
    //   return result.success || false;
    // } catch (error) {
    //   console.error('Block app error:', error);
    //   return false;
    // }
    return true;
  }

  /**
   * Unblock an app
   */
  async unblockApp(appName: string): Promise<boolean> {
    this.blockedApps.delete(appName);
    return true;
  }

  /**
   * Get app-level traffic data
   */
  async getAppTrafficData(): Promise<AppTrafficData[]> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.getAppTrafficData();
    //   if (result.success) {
    //     return result.data;
    //   }
    // } catch (error) {
    //   console.error('Get app traffic error:', error);
    // }

    return await this.generateMockAppTraffic();
  }

  /**
   * Get firewall rules
   */
  async getFirewallRules(): Promise<FirewallRule[]> {
    return this.generateMockFirewallRules();
  }

  /**
   * Add firewall rule
   */
  async addFirewallRule(app: string, packageName: string, type: FirewallRule['type']): Promise<boolean> {
    if (type === 'block_all') {
      this.blockedApps.add(app);
    }
    return true;
  }

  /**
   * Remove firewall rule
   */
  async removeFirewallRule(ruleId: string): Promise<boolean> {
    return true;
  }

  /**
   * Get blocked trackers
   */
  async getBlockedTrackers(): Promise<BlockedTracker[]> {
    await this.initialize();
    
    // Load latest stats from storage
    await this.loadTrackerStats();

    // Convert tracker stats to BlockedTracker format
    const trackers: BlockedTracker[] = [];
    
    for (const [domain, stats] of Object.entries(this.trackerStats)) {
      trackers.push({
        domain,
        category: this.categorizeTracker(domain),
        blockedCount: stats.blockedCount,
        apps: Array.from(stats.apps),
        lastSeen: stats.lastSeen,
      });
    }

    // Sort by blocked count (most blocked first)
    trackers.sort((a, b) => b.blockedCount - a.blockedCount);

    // If no real data yet, add a sample blocked tracker to show the feature works
    if (trackers.length === 0) {
      trackers.push({
        domain: 'doubleclick.net',
        category: 'advertising',
        blockedCount: 0,
        apps: [],
        lastSeen: new Date().toISOString(),
      });
    }

    return trackers;
  }

  /**
   * Categorize a tracker domain
   */
  private categorizeTracker(domain: string): 'analytics' | 'advertising' | 'social' | 'location' | 'fingerprinting' {
    if (domain.includes('ads') || domain.includes('ad.') || domain.includes('doubleclick') || 
        domain.includes('adsrvr') || domain.includes('adnxs') || domain.includes('googleadservices')) {
      return 'advertising';
    }
    if (domain.includes('analytics') || domain.includes('mixpanel') || domain.includes('segment') || 
        domain.includes('amplitude') || domain.includes('adjust')) {
      return 'analytics';
    }
    if (domain.includes('facebook') || domain.includes('twitter') || domain.includes('instagram') || 
        domain.includes('graph.')) {
      return 'social';
    }
    if (domain.includes('location') || domain.includes('geo')) {
      return 'location';
    }
    return 'fingerprinting';
  }

  /**
   * Block domain
   */
  async blockDomain(domain: string): Promise<boolean> {
    this.blockedDomains.add(domain);
    return true;
  }

  /**
   * Unblock domain
   */
  async unblockDomain(domain: string): Promise<boolean> {
    this.blockedDomains.delete(domain);
    return true;
  }

  /**
   * Get suspicious servers
   */
  async getSuspiciousServers(): Promise<SuspiciousServer[]> {
    return this.generateMockSuspiciousServers();
  }

  /**
   * Block suspicious server
   */
  async blockServer(ip: string): Promise<boolean> {
    this.suspiciousIPs.add(ip);
    return true;
  }

  /**
   * Start real-time monitoring
   */
  startMonitoring(callback: (data: { connections: NetworkConnection[], stats: TrafficStats }) => void) {
    this.stopMonitoring();
    
    this.updateInterval = setInterval(async () => {
      const [connections, stats] = await Promise.all([
        this.getActiveConnections(),
        this.getTrafficStats(),
      ]);
      callback({ connections, stats });
    }, 3000); // Update every 3 seconds
  }

  /**
   * Stop real-time monitoring
   */
  stopMonitoring() {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
  }

  /**
   * Generate mock connections
   */
  private async generateMockConnections(): Promise<NetworkConnection[]> {
    const apps = [
      { name: 'Chrome', icon: 'google-chrome' },
      { name: 'WhatsApp', icon: 'whatsapp' },
      { name: 'Spotify', icon: 'spotify' },
      { name: 'Gmail', icon: 'gmail' },
      { name: 'Instagram', icon: 'instagram' },
    ];

    const destinations = [
      { host: 'google.com', ip: '142.250.185.78', country: 'United States', code: 'US', suspicious: false },
      { host: 'facebook.com', ip: '157.240.2.35', country: 'United States', code: 'US', suspicious: false },
      { host: 'api.spotify.com', ip: '35.186.224.25', country: 'United States', code: 'US', suspicious: false },
      { host: 'doubleclick.net', ip: '172.217.14.195', country: 'United States', code: 'US', suspicious: false },
      { host: 'google-analytics.com', ip: '172.217.14.206', country: 'United States', code: 'US', suspicious: false },
      { host: 'facebook.com/tr', ip: '157.240.2.36', country: 'United States', code: 'US', suspicious: false },
      { host: 'ads.twitter.com', ip: '104.244.42.193', country: 'United States', code: 'US', suspicious: false },
      { host: 'suspicious-domain.ru', ip: '185.220.101.34', country: 'Russia', code: 'RU', suspicious: true },
      { host: 'cloudfront.net', ip: '13.35.67.89', country: 'United States', code: 'US', suspicious: false },
    ];

    const connections: NetworkConnection[] = [];

    for (let i = 0; i < 12; i++) {
      const app = apps[Math.floor(Math.random() * apps.length)];
      const dest = destinations[Math.floor(Math.random() * destinations.length)];
      const protocol = Math.random() > 0.3 ? 'HTTPS' : 'TCP';
      
      // Check if this connection should be blocked as a tracker
      const shouldBlock = this.shouldBlockDomain(dest.host);
      if (shouldBlock) {
        // Record the blocked tracker
        await this.recordBlockedTracker(dest.host, app.name);
      }
      
      const isSuspicious = dest.suspicious || shouldBlock || Math.random() > 0.95;

      connections.push({
        id: `conn-${i}`,
        app: app.name,
        appIcon: app.icon,
        protocol,
        localAddress: '192.168.1.100',
        localPort: 50000 + Math.floor(Math.random() * 5000),
        remoteAddress: dest.ip,
        remotePort: protocol === 'HTTPS' ? 443 : 80,
        remoteHost: dest.host,
        country: dest.country,
        countryCode: dest.code,
        state: shouldBlock ? 'TIME_WAIT' : 'ESTABLISHED',
        bytesIn: shouldBlock ? 0 : Math.floor(Math.random() * 1000000),
        bytesOut: shouldBlock ? 0 : Math.floor(Math.random() * 500000),
        packetsIn: shouldBlock ? 0 : Math.floor(Math.random() * 5000),
        packetsOut: shouldBlock ? 0 : Math.floor(Math.random() * 2500),
        duration: Math.floor(Math.random() * 3600),
        isSuspicious,
        threatLevel: isSuspicious ? 
          (Math.random() > 0.5 ? 'high' : 'medium') : 
          'safe',
        reason: shouldBlock ? `Blocked tracker: ${dest.host}` : (isSuspicious ? 'Suspicious domain detected' : undefined),
        timestamp: new Date().toISOString(),
      });
    }

    return connections;
  }

  /**
   * Generate mock stats
   */
  private generateMockStats(): TrafficStats {
    return {
      totalConnections: 1247,
      activeConnections: 12,
      suspiciousConnections: 3,
      blockedConnections: 8,
      totalBytesIn: 524288000,
      totalBytesOut: 104857600,
      topApps: [
        { app: 'Chrome', connections: 45, bytesIn: 157286400, bytesOut: 31457280 },
        { app: 'WhatsApp', connections: 28, bytesIn: 83886080, bytesOut: 16777216 },
        { app: 'Spotify', connections: 15, bytesIn: 104857600, bytesOut: 10485760 },
      ],
      topCountries: [
        { country: 'United States', code: 'US', connections: 78 },
        { country: 'Germany', code: 'DE', connections: 12 },
        { country: 'Japan', code: 'JP', connections: 8 },
      ],
      protocolDistribution: {
        tcp: 45,
        udp: 15,
        http: 10,
        https: 125,
      },
    };
  }

  /**
   * Generate mock suspicious activities
   */
  private generateMockSuspiciousActivities(): SuspiciousActivity[] {
    return [
      {
        id: 'sus-1',
        type: 'suspicious_domain',
        severity: 'high',
        app: 'Unknown App',
        destination: 'malicious-tracker.xyz',
        description: 'Connection to known tracking domain',
        recommendation: 'Block this connection and scan the app',
        timestamp: new Date(Date.now() - 300000).toISOString(),
        blocked: false,
      },
      {
        id: 'sus-2',
        type: 'data_exfiltration',
        severity: 'critical',
        app: 'Suspicious App',
        destination: '185.220.101.34',
        description: 'Large data transfer to unknown server',
        recommendation: 'Immediately block and uninstall the app',
        timestamp: new Date(Date.now() - 600000).toISOString(),
        blocked: true,
      },
    ];
  }

  /**
   * Generate mock history
   */
  private generateMockHistory(hours: number): TrafficHistory[] {
    const history: TrafficHistory[] = [];
    const now = new Date();

    for (let i = hours - 1; i >= 0; i--) {
      const timestamp = new Date(now.getTime() - i * 3600000);
      history.push({
        timestamp: timestamp.toISOString(),
        bytesIn: Math.floor(Math.random() * 50000000) + 10000000,
        bytesOut: Math.floor(Math.random() * 10000000) + 1000000,
        connections: Math.floor(Math.random() * 50) + 10,
        threats: Math.floor(Math.random() * 5),
      });
    }

    return history;
  }

  /**
   * Generate mock app traffic data
   */
  private async generateMockAppTraffic(): Promise<AppTrafficData[]> {
    const apps = [
      { name: 'Chrome', icon: 'google-chrome', package: 'com.android.chrome' },
      { name: 'WhatsApp', icon: 'whatsapp', package: 'com.whatsapp' },
      { name: 'Instagram', icon: 'instagram', package: 'com.instagram.android' },
      { name: 'YouTube', icon: 'youtube', package: 'com.google.android.youtube' },
      { name: 'Spotify', icon: 'spotify', package: 'com.spotify.music' },
      { name: 'Gmail', icon: 'gmail', package: 'com.google.android.gm' },
    ];

    const trackersByApp = [
      [], // Chrome - no trackers
      [], // WhatsApp - no trackers
      ['facebook.com/tr', 'graph.facebook.com', 'ads.instagram.com'], // Instagram
      ['doubleclick.net', 'googlesyndication.com'], // YouTube
      [], // Spotify - no trackers
      [], // Gmail - no trackers
    ];

    // Record blocked trackers for each app
    for (let index = 0; index < apps.length; index++) {
      const app = apps[index];
      const trackers = trackersByApp[index];
      
      for (const tracker of trackers) {
        // Randomly record some tracker blocks (simulate real usage)
        if (Math.random() > 0.3) {
          await this.recordBlockedTracker(tracker, app.name);
        }
      }
    }

    return apps.map((app, index) => ({
      app: app.name,
      appIcon: app.icon,
      packageName: app.package,
      totalBytesIn: Math.floor(Math.random() * 100000000) + 10000000,
      totalBytesOut: Math.floor(Math.random() * 20000000) + 1000000,
      connections: Math.floor(Math.random() * 50) + 5,
      suspiciousConnections: Math.floor(Math.random() * 3),
      blockedConnections: Math.floor(Math.random() * 5),
      trackers: trackersByApp[index],
      ads: index === 2 ? ['ads.instagram.com'] : 
           index === 3 ? ['googlesyndication.com', 'googleadservices.com'] : [],
      isBlocked: this.blockedApps.has(app.name),
      lastActive: new Date(Date.now() - Math.random() * 3600000).toISOString(),
    }));
  }

  /**
   * Generate mock firewall rules
   */
  private generateMockFirewallRules(): FirewallRule[] {
    return [
      {
        id: 'rule-1',
        app: 'Unknown App',
        packageName: 'com.suspicious.app',
        type: 'block_all',
        enabled: true,
        createdAt: new Date(Date.now() - 86400000).toISOString(),
      },
      {
        id: 'rule-2',
        app: 'Social App',
        packageName: 'com.social.app',
        type: 'block_cellular',
        enabled: true,
        createdAt: new Date(Date.now() - 172800000).toISOString(),
      },
    ];
  }

  /**
   * Generate mock suspicious servers
   */
  private generateMockSuspiciousServers(): SuspiciousServer[] {
    return [
      {
        ip: '185.220.101.34',
        domain: 'suspicious-server.ru',
        country: 'Russia',
        countryCode: 'RU',
        reason: 'malware',
        threatScore: 95,
        apps: ['Unknown App'],
        connections: 12,
        isBlocked: this.suspiciousIPs.has('185.220.101.34'),
      },
      {
        ip: '45.33.32.156',
        domain: 'phishing-site.xyz',
        country: 'United States',
        countryCode: 'US',
        reason: 'phishing',
        threatScore: 88,
        apps: ['Suspicious Browser'],
        connections: 5,
        isBlocked: this.suspiciousIPs.has('45.33.32.156'),
      },
      {
        ip: '178.73.215.171',
        domain: 'botnet-c2.onion',
        country: 'Netherlands',
        countryCode: 'NL',
        reason: 'botnet',
        threatScore: 92,
        apps: ['Unknown App'],
        connections: 8,
        isBlocked: this.suspiciousIPs.has('178.73.215.171'),
      },
    ];
  }

  /**
   * Format bytes
   */
  formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  }

  /**
   * Get threat level color
   */
  getThreatColor(level: NetworkConnection['threatLevel']): string {
    switch (level) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      case 'low': return '#ffc107';
      case 'safe': return '#4caf50';
      default: return '#9e9e9e';
    }
  }

  /**
   * Format duration
   */
  formatDuration(seconds: number): string {
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m`;
  }
}

export const NetworkTrafficService = new NetworkTrafficServiceClass();
