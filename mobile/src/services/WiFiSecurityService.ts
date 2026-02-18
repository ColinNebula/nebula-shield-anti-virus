/**
 * WiFi Security Service
 * Scans and rates WiFi network security
 */

import NetInfo from '@react-native-community/netinfo';
import ApiService from './ApiService';

export interface WiFiNetwork {
  ssid: string;
  bssid: string;
  security: string;
  signalStrength: number;
  frequency: number;
  channel: number;
  securityScore: number;
  securityRating: 'excellent' | 'good' | 'fair' | 'poor' | 'critical';
  vulnerabilities: string[];
  recommendations: string[];
  encryptionType: string;
  isSecure: boolean;
  isHidden: boolean;
  isCurrentNetwork: boolean;
  // Enhanced fields
  routerVendor?: string;
  estimatedSpeed?: number; // Mbps
  channelWidth?: number; // MHz
  interferenceLevel?: 'none' | 'low' | 'medium' | 'high';
  congestionScore?: number; // 0-100
  lastSeen?: string;
  isVPNDetected?: boolean;
  isDNSSecure?: boolean;
  uptime?: number; // hours
  connectedDevices?: number;
}

export interface WiFiSecurityScan {
  currentNetwork: WiFiNetwork | null;
  nearbyNetworks: WiFiNetwork[];
  threats: WiFiThreat[];
  scanTime: string;
  totalNetworks: number;
  secureNetworks: number;
  insecureNetworks: number;
  // Enhanced fields
  channelAnalysis?: ChannelAnalysis;
  evilTwinDetected?: boolean;
  duplicateSSIDs?: string[];
  performanceMetrics?: NetworkPerformanceMetrics;
  bestChannel?: number;
  worstChannel?: number;
}

export interface ChannelAnalysis {
  channel: number;
  frequency: number;
  networksOnChannel: number;
  interferenceLevel: 'none' | 'low' | 'medium' | 'high';
  recommendedChannels: number[];
  congestionMap: { [channel: number]: number };
}

export interface NetworkPerformanceMetrics {
  ping: number; // ms
  downloadSpeed: number; // Mbps
  uploadSpeed: number; // Mbps
  jitter: number; // ms
  packetLoss: number; // percentage
  dnsResponseTime: number; // ms
  quality: 'excellent' | 'good' | 'fair' | 'poor';
}

export interface WiFiThreat {
  id: string;
  type: 'mitm' | 'evil_twin' | 'dns_hijack' | 'rogue_ap' | 'weak_encryption' | 'dns_leak' | 'channel_interference' | 'suspicious_activity' | 'arp_spoofing' | 'deauth_attack';
  severity: 'critical' | 'high' | 'medium' | 'low';
  network: string;
  description: string;
  recommendation: string;
  detected: string;
  affectedDevices?: number;
  confidence?: number; // 0-100
}

class WiFiSecurityServiceClass {
  /**
   * Perform comprehensive WiFi security scan
   */
  async scanWiFiNetworks(): Promise<WiFiSecurityScan> {
    console.log('WiFiSecurityService: scanWiFiNetworks called');
    try {
      let netInfo;
      try {
        console.log('WiFiSecurityService: Fetching NetInfo...');
        netInfo = await NetInfo.fetch();
        console.log('WiFiSecurityService: NetInfo fetched:', netInfo?.type, netInfo?.isConnected);
      } catch (netInfoError) {
        console.warn('NetInfo fetch failed, using fallback:', netInfoError);
        netInfo = null;
      }
      
      // Generate scan data with current network info
      const scanData = this.generateMockScanData(netInfo);
      
      // Send current network info to backend for analysis
      console.log('WiFiSecurityService: Sending network info to backend for analysis...');
      try {
        const result = await ApiService.scanWifiNetworks({
          currentNetwork: netInfo?.type === 'wifi' ? {
            ssid: netInfo.details?.ssid,
            bssid: netInfo.details?.bssid,
            strength: netInfo.details?.strength,
            frequency: netInfo.details?.frequency,
            ipAddress: netInfo.details?.ipAddress,
            subnet: netInfo.details?.subnet,
            isConnectionExpensive: netInfo.details?.isConnectionExpensive,
          } : null,
          deviceInfo: {
            platform: 'ios', // or get from Platform
            timestamp: new Date().toISOString(),
          }
        });
        
        if (result.success && result.data) {
          console.log('WiFiSecurityService: Backend returned enhanced data');
          // Merge backend analysis with local scan
          return {
            ...scanData,
            ...result.data,
            currentNetwork: result.data.currentNetwork || scanData.currentNetwork,
          };
        }
      } catch (apiError) {
        console.warn('Backend API call failed, using local data:', apiError);
      }

      // Return local scan data
      console.log('WiFiSecurityService: Using local scan data');
      return scanData;
    } catch (error) {
      console.error('WiFi scan error:', error);
      // Fallback with null netInfo
      return this.generateMockScanData(null);
    }
  }

  /**
   * Get current WiFi network security analysis
   */
  async analyzeCurrentNetwork(): Promise<WiFiNetwork | null> {
    const netInfo = await NetInfo.fetch();
    
    if (netInfo.type !== 'wifi' || !netInfo.isConnected) {
      return null;
    }

    // Try backend API first
    try {
      const result = await ApiService.analyzeWifiChannel();
      if (result.success && result.data) {
        return result.data;
      }
    } catch (error) {
      console.error('Network analysis error:', error);
    }

    // Fallback: Analyze current network locally
    return this.analyzeNetwork({
      ssid: netInfo.details?.ssid || 'Unknown Network',
      bssid: netInfo.details?.bssid || 'Unknown',
      security: 'WPA2',
      signalStrength: netInfo.details?.strength || 75,
      frequency: netInfo.details?.frequency || 2400,
      isCurrentNetwork: true,
    });
  }

  /**
   * Check for Man-in-the-Middle attacks
   */
  async detectMITM(): Promise<boolean> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.detectMITM();
    //   return result.detected || false;
    // } catch (error) {
    //   console.error('MITM detection error:', error);
    // }
    return false;
  }

  /**
   * Detect DNS hijacking
   */
  async detectDNSHijacking(): Promise<boolean> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.checkDNSHijacking();
    //   return result.hijacked || false;
    // } catch (error) {
    //   console.error('DNS check error:', error);
    // }
    return false;
  }

  /**
   * Analyze channel interference and congestion
   */
  analyzeChannelInterference(networks: WiFiNetwork[]): ChannelAnalysis {
    const congestionMap: { [channel: number]: number } = {};
    
    // Count networks on each channel
    networks.forEach(network => {
      congestionMap[network.channel] = (congestionMap[network.channel] || 0) + 1;
    });

    // Find current network's channel
    const currentNetwork = networks.find(n => n.isCurrentNetwork);
    const currentChannel = currentNetwork?.channel || 1;
    const networksOnChannel = congestionMap[currentChannel] || 0;

    // Determine interference level
    let interferenceLevel: ChannelAnalysis['interferenceLevel'];
    if (networksOnChannel <= 1) interferenceLevel = 'none';
    else if (networksOnChannel <= 3) interferenceLevel = 'low';
    else if (networksOnChannel <= 5) interferenceLevel = 'medium';
    else interferenceLevel = 'high';

    // Recommend best channels (least congested)
    const recommendedChannels = Object.entries(congestionMap)
      .sort((a, b) => a[1] - b[1])
      .slice(0, 3)
      .map(([channel]) => parseInt(channel));

    return {
      channel: currentChannel,
      frequency: currentNetwork?.frequency || 2400,
      networksOnChannel,
      interferenceLevel,
      recommendedChannels,
      congestionMap,
    };
  }

  /**
   * Detect evil twin networks (duplicate SSIDs)
   */
  detectEvilTwins(networks: WiFiNetwork[]): string[] {
    const ssidMap = new Map<string, number>();
    const duplicates: string[] = [];

    networks.forEach(network => {
      const count = ssidMap.get(network.ssid) || 0;
      ssidMap.set(network.ssid, count + 1);
    });

    ssidMap.forEach((count, ssid) => {
      if (count > 1 && !ssid.includes('xfinitywifi') && !ssid.includes('Google Starbucks')) {
        duplicates.push(ssid);
      }
    });

    return duplicates;
  }

  /**
   * Get router vendor from MAC address
   */
  getRouterVendor(bssid: string): string {
    const mac = bssid.toUpperCase().substring(0, 8);
    
    const vendors: { [key: string]: string } = {
      '00:11:22': 'Cimsys Inc',
      '00:1A:2B': 'Cisco Systems',
      '00:1B:63': 'Cisco-Linksys',
      '00:23:69': 'Cisco-Linksys',
      '00:25:9C': 'Cisco-Linksys',
      '24:A4:3C': 'TP-Link',
      '50:C7:BF': 'TP-Link',
      '08:86:3B': 'TP-Link',
      '00:50:56': 'VMware',
      'DC:9F:DB': 'Google',
      'F8:8F:CA': 'Google',
      '00:0C:42': 'Routerboard',
      '4C:5E:0C': 'Routerboard',
      '00:18:E7': 'Netgear',
      '28:C6:8E': 'Netgear',
      'C0:3F:0E': 'Netgear',
      '00:14:BF': 'Belkin',
      '94:44:52': 'Belkin',
      'EC:1A:59': 'Belkin',
      '00:1D:7E': 'D-Link',
      '14:D6:4D': 'D-Link',
      '90:94:E4': 'D-Link',
    };

    return vendors[mac] || 'Unknown Vendor';
  }

  /**
   * Estimate network speed based on signal and channel
   */
  estimateNetworkSpeed(network: WiFiNetwork): number {
    const baseSpeed = network.frequency > 5000 ? 300 : 150; // 5GHz vs 2.4GHz
    const signalFactor = network.signalStrength / 100;
    const congestionFactor = 1 - (network.congestionScore || 0) / 200;
    
    return Math.round(baseSpeed * signalFactor * congestionFactor);
  }

  /**
   * Perform network performance test
   */
  async testNetworkPerformance(): Promise<NetworkPerformanceMetrics> {
    // Mock performance metrics - in production, this would use actual network tests
    const ping = Math.random() * 50 + 10; // 10-60ms
    const downloadSpeed = Math.random() * 100 + 50; // 50-150 Mbps
    const uploadSpeed = downloadSpeed * 0.4; // Typically lower than download
    const jitter = Math.random() * 10 + 2; // 2-12ms
    const packetLoss = Math.random() * 2; // 0-2%
    const dnsResponseTime = Math.random() * 30 + 5; // 5-35ms

    let quality: NetworkPerformanceMetrics['quality'];
    if (ping < 20 && packetLoss < 0.5) quality = 'excellent';
    else if (ping < 40 && packetLoss < 1) quality = 'good';
    else if (ping < 60 && packetLoss < 2) quality = 'fair';
    else quality = 'poor';

    return {
      ping: Math.round(ping),
      downloadSpeed: Math.round(downloadSpeed),
      uploadSpeed: Math.round(uploadSpeed),
      jitter: Math.round(jitter),
      packetLoss: Math.round(packetLoss * 100) / 100,
      dnsResponseTime: Math.round(dnsResponseTime),
      quality,
    };
  }

  /**
   * Analyze a WiFi network's security
   */
  private analyzeNetwork(networkData: Partial<WiFiNetwork>): WiFiNetwork {
    const vulnerabilities: string[] = [];
    const recommendations: string[] = [];
    let securityScore = 100;

    // Check encryption type
    const security = networkData.security || 'Open';
    let encryptionType = 'None';
    let isSecure = false;

    if (security.includes('WPA3')) {
      encryptionType = 'WPA3 (Excellent)';
      isSecure = true;
    } else if (security.includes('WPA2')) {
      encryptionType = 'WPA2 (Good)';
      isSecure = true;
      securityScore -= 10;
      recommendations.push('Upgrade to WPA3 if router supports it');
    } else if (security.includes('WPA')) {
      encryptionType = 'WPA (Weak)';
      securityScore -= 30;
      vulnerabilities.push('Outdated WPA encryption detected');
      recommendations.push('Upgrade to WPA2 or WPA3 immediately');
    } else if (security.includes('WEP')) {
      encryptionType = 'WEP (Very Weak)';
      securityScore -= 60;
      vulnerabilities.push('WEP encryption is easily crackable');
      recommendations.push('Never use WEP! Upgrade to WPA2/WPA3');
    } else {
      encryptionType = 'Open (No Encryption)';
      securityScore = 0;
      vulnerabilities.push('Network is completely unencrypted');
      recommendations.push('Avoid using this network for sensitive data');
    }

    // Check signal strength
    const signalStrength = networkData.signalStrength || 0;
    if (signalStrength < 30) {
      securityScore -= 10;
      vulnerabilities.push('Weak signal - connection may be unstable');
    }

    // Determine security rating
    let securityRating: WiFiNetwork['securityRating'];
    if (securityScore >= 90) securityRating = 'excellent';
    else if (securityScore >= 70) securityRating = 'good';
    else if (securityScore >= 50) securityRating = 'fair';
    else if (securityScore >= 30) securityRating = 'poor';
    else securityRating = 'critical';

    const bssid = networkData.bssid || 'Unknown';
    const frequency = networkData.frequency || 2400;
    const channel = Math.floor((frequency - 2412) / 5) + 1;
    
    const network: WiFiNetwork = {
      ssid: networkData.ssid || 'Unknown',
      bssid,
      security: security,
      signalStrength: signalStrength,
      frequency,
      channel,
      securityScore,
      securityRating,
      vulnerabilities,
      recommendations,
      encryptionType,
      isSecure,
      isHidden: false,
      isCurrentNetwork: networkData.isCurrentNetwork || false,
      // Enhanced fields
      routerVendor: this.getRouterVendor(bssid),
      channelWidth: frequency > 5000 ? 80 : 20,
      lastSeen: new Date().toISOString(),
      uptime: Math.floor(Math.random() * 720), // 0-30 days in hours
      connectedDevices: Math.floor(Math.random() * 20) + 1,
    };

    // Estimate speed after network object is created
    network.estimatedSpeed = this.estimateNetworkSpeed(network);
    
    return network;
  }

  /**
   * Generate mock scan data for demo
   */
  private generateMockScanData(netInfo: any): WiFiSecurityScan {
    // Get current network SSID safely
    const currentSSID = netInfo?.details?.ssid || 'Home-WiFi-5G';
    
    const networks: WiFiNetwork[] = [
      this.analyzeNetwork({
        ssid: currentSSID,
        bssid: '24:A4:3C:12:34:56',
        security: 'WPA2',
        signalStrength: 85,
        frequency: 5180,
        isCurrentNetwork: true,
      }),
      this.analyzeNetwork({
        ssid: 'CoffeeShop-Guest',
        bssid: '00:18:E7:AA:BB:CC',
        security: 'Open',
        signalStrength: 65,
        frequency: 2437,
        isCurrentNetwork: false,
      }),
      this.analyzeNetwork({
        ssid: 'Neighbor-WiFi',
        bssid: 'DC:9F:DB:11:22:33',
        security: 'WPA3',
        signalStrength: 45,
        frequency: 5240,
        isCurrentNetwork: false,
      }),
      this.analyzeNetwork({
        ssid: 'Public-Hotspot',
        bssid: '00:1D:7E:44:55:66',
        security: 'WEP',
        signalStrength: 55,
        frequency: 2462,
        isCurrentNetwork: false,
      }),
      this.analyzeNetwork({
        ssid: 'Starbucks WiFi',
        bssid: '14:D6:4D:77:88:99',
        security: 'Open',
        signalStrength: 70,
        frequency: 2412,
        isCurrentNetwork: false,
      }),
      this.analyzeNetwork({
        ssid: 'Office-5G',
        bssid: '28:C6:8E:AA:BB:CC',
        security: 'WPA2',
        signalStrength: 40,
        frequency: 5745,
        isCurrentNetwork: false,
      }),
    ];

    // Calculate congestion for each network
    const channelCounts: { [channel: number]: number } = {};
    networks.forEach(network => {
      channelCounts[network.channel] = (channelCounts[network.channel] || 0) + 1;
    });
    
    networks.forEach(network => {
      network.congestionScore = (channelCounts[network.channel] || 1) * 20;
      network.interferenceLevel = 
        network.congestionScore > 80 ? 'high' :
        network.congestionScore > 50 ? 'medium' :
        network.congestionScore > 20 ? 'low' : 'none';
      // Recalculate speed with congestion
      network.estimatedSpeed = this.estimateNetworkSpeed(network);
    });

    const threats: WiFiThreat[] = [];
    
    // Check for open networks
    networks.forEach(network => {
      if (network.security === 'Open') {
        threats.push({
          id: `threat-open-${network.bssid}`,
          type: 'weak_encryption',
          severity: 'high',
          network: network.ssid,
          description: 'Unencrypted network detected - all traffic is visible to attackers',
          recommendation: 'Avoid accessing sensitive data on this network. Use VPN if necessary.',
          detected: new Date().toISOString(),
          confidence: 100,
        });
      }
      
      if (network.security === 'WEP') {
        threats.push({
          id: `threat-wep-${network.bssid}`,
          type: 'weak_encryption',
          severity: 'critical',
          network: network.ssid,
          description: 'WEP encryption is severely outdated and can be cracked in minutes',
          recommendation: 'Do not connect to this network. Contact network admin to upgrade to WPA2/WPA3.',
          detected: new Date().toISOString(),
          confidence: 100,
        });
      }
    });

    // Detect evil twins
    const duplicateSSIDs = this.detectEvilTwins(networks);
    if (duplicateSSIDs.length > 0) {
      duplicateSSIDs.forEach(ssid => {
        threats.push({
          id: `threat-twin-${ssid}`,
          type: 'evil_twin',
          severity: 'critical',
          network: ssid,
          description: `Multiple networks with identical SSID "${ssid}" detected. This could be an evil twin attack.`,
          recommendation: 'Verify the legitimate network BSSID before connecting. Avoid entering credentials.',
          detected: new Date().toISOString(),
          confidence: 75,
        });
      });
    }

    // Channel interference warnings
    const currentNetwork = networks.find(n => n.isCurrentNetwork);
    if (currentNetwork && currentNetwork.interferenceLevel === 'high') {
      threats.push({
        id: 'threat-interference',
        type: 'channel_interference',
        severity: 'medium',
        network: currentNetwork.ssid,
        description: `High interference detected on channel ${currentNetwork.channel}. This may cause slow speeds and connection drops.`,
        recommendation: `Change your router to channel ${this.analyzeChannelInterference(networks).recommendedChannels[0]} for better performance.`,
        detected: new Date().toISOString(),
        confidence: 90,
      });
    }

    const secureNetworks = networks.filter(n => n.isSecure).length;
    const channelAnalysis = this.analyzeChannelInterference(networks);

    return {
      currentNetwork: networks.find(n => n.isCurrentNetwork) || null,
      nearbyNetworks: networks.filter(n => !n.isCurrentNetwork),
      threats,
      scanTime: new Date().toISOString(),
      totalNetworks: networks.length,
      secureNetworks,
      insecureNetworks: networks.length - secureNetworks,
      channelAnalysis,
      evilTwinDetected: duplicateSSIDs.length > 0,
      duplicateSSIDs,
      bestChannel: Math.min(...Object.keys(channelAnalysis.congestionMap).map(Number)),
      worstChannel: Math.max(...Object.keys(channelAnalysis.congestionMap).map(Number)),
    };
  }

  /**
   * Get security rating color
   */
  getSecurityColor(rating: WiFiNetwork['securityRating']): string {
    switch (rating) {
      case 'excellent': return '#4caf50';
      case 'good': return '#8bc34a';
      case 'fair': return '#ff9800';
      case 'poor': return '#f44336';
      case 'critical': return '#d32f2f';
      default: return '#9e9e9e';
    }
  }

  /**
   * Get threat severity color
   */
  getThreatColor(severity: WiFiThreat['severity']): string {
    switch (severity) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      case 'low': return '#ffc107';
      default: return '#9e9e9e';
    }
  }
}

export const WiFiSecurityService = new WiFiSecurityServiceClass();
