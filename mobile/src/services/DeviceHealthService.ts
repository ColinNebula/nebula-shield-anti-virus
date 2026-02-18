/**
 * Device Health Service
 * Monitors mobile device health, security status, and performance
 * Works on both iOS and Android
 */

import NetInfo from '@react-native-community/netinfo';
import { Platform } from 'react-native';
import VPNService from './VPNService';

// Try to import real DeviceInfo, fallback to mock for Expo Go
let DeviceInfo: any;
let isUsingRealDeviceInfo = false;

try {
  DeviceInfo = require('react-native-device-info');
  isUsingRealDeviceInfo = true;
  console.log('✅ Using REAL device data from react-native-device-info');
} catch (error) {
  console.log('⚠️ Using MOCK device data (Expo Go compatibility mode)');
  // Mock DeviceInfo for Expo Go compatibility
  DeviceInfo = {
    default: {
      isJailbroken: async () => false,
      isRooted: async () => false,
      isEmulator: async () => false,
      isPinOrFingerprintSet: async () => true,
      getBatteryLevel: async () => 0.75,
      getTotalMemory: async () => 4 * 1024 * 1024 * 1024,
      getFreeDiskStorage: async () => 10 * 1024 * 1024 * 1024,
      getTotalDiskCapacity: async () => 64 * 1024 * 1024 * 1024,
      getPowerState: async () => ({ batteryState: 'unplugged' }),
      getModel: async () => 'Expo Go Device',
      getBrand: async () => Platform.OS === 'ios' ? 'Apple' : 'Android',
      getSystemVersion: async () => Platform.Version.toString(),
      getVersion: async () => '1.0.0',
    }
  };
}

// Normalize the API (handle both default export and direct import)
const Device = DeviceInfo.default || DeviceInfo;

export interface DeviceHealthData {
  security: {
    isJailbroken: boolean;
    isRooted: boolean;
    isEmulator: boolean;
    isPinOrFingerprintSet: boolean;
    securityScore: number;
  };
  performance: {
    batteryLevel: number;
    isCharging: boolean;
    totalMemory: number;
    freeStorage: number;
    totalStorage: number;
    storageUsagePercent: number;
  };
  network: {
    isConnected: boolean;
    type: string;
    isWifi: boolean;
    isVpnActive: boolean;
  };
  device: {
    model: string;
    brand: string;
    systemVersion: string;
    platform: string;
    appVersion: string;
  };
  timestamp: string;
  dataSource: 'real' | 'mock'; // Indicates if using real or simulated data
}

class DeviceHealthServiceClass {
  /**
   * Get comprehensive device health data
   */
  async getDeviceHealth(): Promise<DeviceHealthData> {
    try {
      const [security, performance, network, device] = await Promise.all([
        this.getSecurityStatus(),
        this.getPerformanceMetrics(),
        this.getNetworkStatus(),
        this.getDeviceInfo(),
      ]);

      return {
        security,
        performance,
        network,
        device,
        timestamp: new Date().toISOString(),
        dataSource: isUsingRealDeviceInfo ? 'real' : 'mock',
      };
    } catch (error) {
      console.error('Error getting device health:', error);
      throw error;
    }
  }

  /**
   * Check device security status
   */
  private async getSecurityStatus() {
    const [isJailbroken, isEmulator, isPinOrFingerprintSet] = await Promise.all([
      Platform.OS === 'ios' 
        ? Device.isJailbroken()
        : Device.isRooted(),
      Device.isEmulator(),
      Device.isPinOrFingerprintSet(),
    ]);

    // Calculate security score (0-100)
    let securityScore = 100;
    
    if (isJailbroken) securityScore -= 50; // Major security risk
    if (isEmulator) securityScore -= 20; // Emulators are less secure
    if (!isPinOrFingerprintSet) securityScore -= 30; // No device lock

    return {
      isJailbroken: Platform.OS === 'ios' ? isJailbroken : false,
      isRooted: Platform.OS === 'android' ? isJailbroken : false,
      isEmulator,
      isPinOrFingerprintSet,
      securityScore: Math.max(0, securityScore),
    };
  }

  /**
   * Get device performance metrics
   */
  private async getPerformanceMetrics() {
    const [batteryLevel, totalMemory, freeStorage, totalStorage, powerState] = await Promise.all([
      Device.getBatteryLevel(),
      Device.getTotalMemory(),
      Device.getFreeDiskStorage(),
      Device.getTotalDiskCapacity(),
      Device.getPowerState(),
    ]);

    const storageUsagePercent = Math.round(
      ((totalStorage - freeStorage) / totalStorage) * 100
    );

    return {
      batteryLevel: Math.round(batteryLevel * 100),
      isCharging: powerState.batteryState === 'charging' || powerState.batteryState === 'full',
      totalMemory: Math.round(totalMemory / (1024 * 1024 * 1024)), // Convert to GB
      freeStorage: Math.round(freeStorage / (1024 * 1024 * 1024)), // Convert to GB
      totalStorage: Math.round(totalStorage / (1024 * 1024 * 1024)), // Convert to GB
      storageUsagePercent,
    };
  }

  /**
   * Get network connection status
   */
  private async getNetworkStatus() {
    const netInfo = await NetInfo.fetch();
    
    // Check actual VPN status from backend
    let isVpnActive = false;
    try {
      const vpnStatus = await VPNService.getStatus();
      isVpnActive = vpnStatus.success && vpnStatus.data?.connected === true;
    } catch (error) {
      console.log('Could not fetch VPN status:', error);
      // Fallback to rough detection
      isVpnActive = netInfo.details?.isConnectionExpensive === true;
    }

    return {
      isConnected: netInfo.isConnected || false,
      type: netInfo.type || 'unknown',
      isWifi: netInfo.type === 'wifi',
      isVpnActive,
    };
  }

  /**
   * Get device information
   */
  private async getDeviceInfo() {
    const [model, brand, systemVersion, appVersion] = await Promise.all([
      Device.getModel(),
      Device.getBrand(),
      Device.getSystemVersion(),
      Device.getVersion(),
    ]);

    return {
      model,
      brand,
      systemVersion,
      platform: Platform.OS,
      appVersion,
    };
  }

  /**
   * Get security recommendations based on device status
   */
  async getSecurityRecommendations(): Promise<string[]> {
    const health = await this.getDeviceHealth();
    const recommendations: string[] = [];

    if (health.security.isJailbroken || health.security.isRooted) {
      recommendations.push(
        '🔴 CRITICAL: Your device is jailbroken/rooted. This significantly reduces security. Consider restoring to factory settings.'
      );
    }

    if (!health.security.isPinOrFingerprintSet) {
      recommendations.push(
        '⚠️ Enable device lock (PIN/fingerprint/Face ID) to protect your data if device is lost or stolen.'
      );
    }

    if (health.performance.batteryLevel < 20 && !health.performance.isCharging) {
      recommendations.push(
        '🔋 Low battery. Charge your device to ensure security features remain active.'
      );
    }

    if (health.performance.storageUsagePercent > 90) {
      recommendations.push(
        '💾 Storage almost full. Free up space to ensure smooth operation and security updates.'
      );
    }

    if (!health.network.isWifi && health.network.isConnected) {
      recommendations.push(
        '📱 Using cellular data. Be cautious when accessing sensitive information on public networks.'
      );
    }

    if (health.network.isConnected && !health.network.isVpnActive) {
      recommendations.push(
        '🌐 Not using VPN. Consider enabling VPN when on public networks for enhanced privacy.'
      );
    }

    if (recommendations.length === 0) {
      recommendations.push('✅ Your device security looks good! Keep following best practices.');
    }

    return recommendations;
  }

  /**
   * Quick health check - returns true if device is secure
   */
  async isDeviceSecure(): Promise<boolean> {
    const health = await this.getDeviceHealth();
    
    return (
      !health.security.isJailbroken &&
      !health.security.isRooted &&
      health.security.isPinOrFingerprintSet &&
      health.security.securityScore >= 70
    );
  }

  /**
   * Check if using real device data or mock data
   */
  isUsingRealData(): boolean {
    return isUsingRealDeviceInfo;
  }

  /**
   * Get data source description
   */
  getDataSourceInfo(): string {
    return isUsingRealDeviceInfo
      ? '✅ Using real device data'
      : '⚠️ Using simulated data (Expo Go mode)';
  }
}

export const DeviceHealthService = new DeviceHealthServiceClass();
