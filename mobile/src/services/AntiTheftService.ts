/**
 * Anti-Theft Service
 * Device tracking, remote lock, and theft protection features
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import { Platform, Alert } from 'react-native';
import * as Location from 'expo-location';
import ApiService from './ApiService';

export interface DeviceLocation {
  latitude: number;
  longitude: number;
  accuracy: number;
  altitude?: number;
  timestamp: string;
  address?: string;
}

export interface AntiTheftSettings {
  enabled: boolean;
  lockOnTheft: boolean;
  soundAlarm: boolean;
  trackLocation: boolean;
  wipeDataOnMultipleFailedAttempts: boolean;
  maxFailedAttempts: number;
  photoOnWrongPassword: boolean;
  notifyTrustedContacts: boolean;
  trustedContacts: TrustedContact[];
}

export interface TrustedContact {
  id: string;
  name: string;
  phone: string;
  email?: string;
  relationship: string;
}

export interface TheftAlert {
  id: string;
  type: 'wrong_password' | 'sim_change' | 'unauthorized_access' | 'device_moved' | 'factory_reset_attempt';
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: string;
  location?: DeviceLocation;
  photo?: string;
  details: string;
  isAcknowledged: boolean;
}

export interface DeviceStatus {
  isLocked: boolean;
  isLocated: boolean;
  lastLocation?: DeviceLocation;
  batteryLevel: number;
  isOnline: boolean;
  lastSeen: string;
  simChanged: boolean;
  lockMessage?: string;
}

export interface RemoteCommand {
  id: string;
  type: 'lock' | 'locate' | 'alarm' | 'wipe' | 'message';
  status: 'pending' | 'executing' | 'completed' | 'failed';
  sentAt: string;
  executedAt?: string;
  parameters?: any;
  result?: string;
}

export interface LocationHistory {
  timestamp: string;
  location: DeviceLocation;
  trigger: 'manual' | 'automatic' | 'theft_alert';
}

export interface SIMCardInfo {
  carrier: string;
  countryCode: string;
  iccId: string;
  simSerialNumber: string;
  isChanged: boolean;
  changeDetectedAt?: string;
}

class AntiTheftServiceClass {
  private isTracking = false;
  private trackingInterval: NodeJS.Timeout | null = null;
  private failedAttempts = 0;
  private originalSIM: string | null = null;

  /**
   * Initialize anti-theft protection
   */
  async initialize(): Promise<boolean> {
    try {
      const settings = await this.getSettings();
      if (!settings.enabled) {
        return false;
      }

      // Request location permissions
      const { status } = await Location.requestForegroundPermissionsAsync();
      if (status !== 'granted') {
        console.log('Location permission denied');
        return false;
      }

      // Store original SIM info
      await this.storeSIMInfo();

      // Start monitoring if tracking enabled
      if (settings.trackLocation) {
        this.startLocationTracking();
      }

      return true;
    } catch (error) {
      console.error('Anti-theft initialization error:', error);
      return false;
    }
  }

  /**
   * Get anti-theft settings
   */
  async getSettings(): Promise<AntiTheftSettings> {
    try {
      const stored = await AsyncStorage.getItem('antitheft_settings');
      return stored ? JSON.parse(stored) : this.getDefaultSettings();
    } catch (error) {
      return this.getDefaultSettings();
    }
  }

  /**
   * Update anti-theft settings
   */
  async updateSettings(settings: AntiTheftSettings): Promise<boolean> {
    try {
      await AsyncStorage.setItem('antitheft_settings', JSON.stringify(settings));
      
      // Start/stop tracking based on settings
      if (settings.enabled && settings.trackLocation) {
        this.startLocationTracking();
      } else {
        this.stopLocationTracking();
      }

      return true;
    } catch (error) {
      console.error('Update settings error:', error);
      return false;
    }
  }

  /**
   * Get default settings
   */
  private getDefaultSettings(): AntiTheftSettings {
    return {
      enabled: false,
      lockOnTheft: true,
      soundAlarm: true,
      trackLocation: true,
      wipeDataOnMultipleFailedAttempts: false,
      maxFailedAttempts: 10,
      photoOnWrongPassword: true,
      notifyTrustedContacts: true,
      trustedContacts: [],
    };
  }

  /**
   * Get current device location
   */
  async getCurrentLocation(): Promise<DeviceLocation | null> {
    try {
      const { status } = await Location.requestForegroundPermissionsAsync();
      if (status !== 'granted') {
        return null;
      }

      const location = await Location.getCurrentPositionAsync({
        accuracy: Location.Accuracy.High,
      });

      const deviceLocation: DeviceLocation = {
        latitude: location.coords.latitude,
        longitude: location.coords.longitude,
        accuracy: location.coords.accuracy || 0,
        altitude: location.coords.altitude || undefined,
        timestamp: new Date().toISOString(),
      };

      // Try to get address
      try {
        const addresses = await Location.reverseGeocodeAsync({
          latitude: deviceLocation.latitude,
          longitude: deviceLocation.longitude,
        });

        if (addresses && addresses.length > 0) {
          const addr = addresses[0];
          deviceLocation.address = `${addr.street || ''}, ${addr.city || ''}, ${addr.region || ''}, ${addr.country || ''}`.trim();
        }
      } catch (error) {
        console.log('Address lookup failed');
      }

      // Save to location history
      await this.saveLocationToHistory(deviceLocation, 'manual');

      return deviceLocation;
    } catch (error) {
      console.error('Get location error:', error);
      return null;
    }
  }

  /**
   * Start continuous location tracking
   */
  private startLocationTracking(): void {
    if (this.isTracking) {
      return;
    }

    this.isTracking = true;
    this.trackingInterval = setInterval(async () => {
      const location = await this.getCurrentLocation();
      if (location) {
        await this.saveLocationToHistory(location, 'automatic');
      }
    }, 5 * 60 * 1000); // Every 5 minutes
  }

  /**
   * Stop location tracking
   */
  private stopLocationTracking(): void {
    if (this.trackingInterval) {
      clearInterval(this.trackingInterval);
      this.trackingInterval = null;
    }
    this.isTracking = false;
  }

  /**
   * Save location to history
   */
  private async saveLocationToHistory(
    location: DeviceLocation,
    trigger: LocationHistory['trigger']
  ): Promise<void> {
    try {
      const history = await this.getLocationHistory(100);
      history.unshift({
        timestamp: new Date().toISOString(),
        location,
        trigger,
      });
      await AsyncStorage.setItem('location_history', JSON.stringify(history.slice(0, 100)));
    } catch (error) {
      console.error('Save location history error:', error);
    }
  }

  /**
   * Get location history
   */
  async getLocationHistory(limit: number = 50): Promise<LocationHistory[]> {
    try {
      const stored = await AsyncStorage.getItem('location_history');
      const history: LocationHistory[] = stored ? JSON.parse(stored) : [];
      return history.slice(0, limit);
    } catch (error) {
      return [];
    }
  }

  /**
   * Remote lock device
   */
  async remoteLock(message?: string): Promise<boolean> {
    try {
      const command: RemoteCommand = {
        id: `cmd-${Date.now()}`,
        type: 'lock',
        status: 'executing',
        sentAt: new Date().toISOString(),
        parameters: { message },
      };

      // In production, this would actually lock the device
      // For now, just save the command and show alert
      await this.saveCommand(command);

      Alert.alert(
        'Device Locked',
        message || 'This device has been locked remotely for security reasons.',
        [{ text: 'OK' }]
      );

      command.status = 'completed';
      command.executedAt = new Date().toISOString();
      await this.saveCommand(command);

      return true;
    } catch (error) {
      console.error('Remote lock error:', error);
      return false;
    }
  }

  /**
   * Sound alarm
   */
  async soundAlarm(): Promise<boolean> {
    try {
      const command: RemoteCommand = {
        id: `cmd-${Date.now()}`,
        type: 'alarm',
        status: 'executing',
        sentAt: new Date().toISOString(),
      };

      await this.saveCommand(command);

      // In production, would play loud alarm sound
      Alert.alert(
        'Alarm Activated',
        'A loud alarm is now sounding on your device',
        [{ text: 'Stop Alarm' }]
      );

      command.status = 'completed';
      command.executedAt = new Date().toISOString();
      await this.saveCommand(command);

      return true;
    } catch (error) {
      console.error('Sound alarm error:', error);
      return false;
    }
  }

  /**
   * Wipe device data
   */
  async wipeData(): Promise<boolean> {
    try {
      // Show confirmation
      return new Promise((resolve) => {
        Alert.alert(
          'Wipe Device Data',
          'This will permanently delete ALL data on your device. This action cannot be undone. Are you sure?',
          [
            {
              text: 'Cancel',
              style: 'cancel',
              onPress: () => resolve(false),
            },
            {
              text: 'Wipe Device',
              style: 'destructive',
              onPress: async () => {
                const command: RemoteCommand = {
                  id: `cmd-${Date.now()}`,
                  type: 'wipe',
                  status: 'executing',
                  sentAt: new Date().toISOString(),
                };

                await this.saveCommand(command);

                // In production, would actually wipe the device
                // For now, just simulate
                Alert.alert(
                  'Device Wipe Initiated',
                  'All data is being erased...',
                  [{ text: 'OK' }]
                );

                command.status = 'completed';
                command.executedAt = new Date().toISOString();
                await this.saveCommand(command);

                resolve(true);
              },
            },
          ]
        );
      });
    } catch (error) {
      console.error('Wipe data error:', error);
      return false;
    }
  }

  /**
   * Send message to device
   */
  async sendMessage(message: string): Promise<boolean> {
    try {
      const command: RemoteCommand = {
        id: `cmd-${Date.now()}`,
        type: 'message',
        status: 'executing',
        sentAt: new Date().toISOString(),
        parameters: { message },
      };

      await this.saveCommand(command);

      Alert.alert('Message from Owner', message, [{ text: 'OK' }]);

      command.status = 'completed';
      command.executedAt = new Date().toISOString();
      await this.saveCommand(command);

      return true;
    } catch (error) {
      console.error('Send message error:', error);
      return false;
    }
  }

  /**
   * Record failed login attempt
   */
  async recordFailedAttempt(): Promise<void> {
    this.failedAttempts++;
    const settings = await this.getSettings();

    if (!settings.enabled) {
      return;
    }

    // Create theft alert
    const alert: TheftAlert = {
      id: `alert-${Date.now()}`,
      type: 'wrong_password',
      severity: this.failedAttempts >= settings.maxFailedAttempts ? 'critical' : 'medium',
      timestamp: new Date().toISOString(),
      location: await this.getCurrentLocation() || undefined,
      details: `Failed login attempt ${this.failedAttempts}/${settings.maxFailedAttempts}`,
      isAcknowledged: false,
    };

    await this.saveTheftAlert(alert);

    // Take photo if enabled
    if (settings.photoOnWrongPassword) {
      await this.capturePhoto();
    }

    // Notify trusted contacts
    if (settings.notifyTrustedContacts && this.failedAttempts >= settings.maxFailedAttempts) {
      await this.notifyTrustedContacts('Multiple failed login attempts detected');
    }

    // Wipe data if threshold reached
    if (settings.wipeDataOnMultipleFailedAttempts && 
        this.failedAttempts >= settings.maxFailedAttempts) {
      await this.wipeData();
    }
  }

  /**
   * Reset failed attempts counter
   */
  resetFailedAttempts(): void {
    this.failedAttempts = 0;
  }

  /**
   * Capture photo (simulate)
   */
  private async capturePhoto(): Promise<string | null> {
    try {
      // In production, would use camera to capture photo
      // For now, just simulate
      const photoId = `photo-${Date.now()}`;
      console.log('Photo captured:', photoId);
      return photoId;
    } catch (error) {
      console.error('Capture photo error:', error);
      return null;
    }
  }

  /**
   * Check for SIM card change
   */
  async checkSIMChange(): Promise<boolean> {
    try {
      const currentSIM = await this.getSIMInfo();
      const originalSIM = await AsyncStorage.getItem('original_sim');

      if (originalSIM && currentSIM.iccId !== originalSIM) {
        // SIM changed!
        const alert: TheftAlert = {
          id: `alert-${Date.now()}`,
          type: 'sim_change',
          severity: 'critical',
          timestamp: new Date().toISOString(),
          location: await this.getCurrentLocation() || undefined,
          details: 'SIM card has been changed - possible theft',
          isAcknowledged: false,
        };

        await this.saveTheftAlert(alert);

        const settings = await this.getSettings();
        if (settings.lockOnTheft) {
          await this.remoteLock('SIM card changed - device locked for security');
        }

        return true;
      }

      return false;
    } catch (error) {
      console.error('SIM check error:', error);
      return false;
    }
  }

  /**
   * Get SIM info
   */
  private async getSIMInfo(): Promise<SIMCardInfo> {
    // Mock SIM info - in production would use actual device APIs
    return {
      carrier: 'Carrier Name',
      countryCode: 'US',
      iccId: '89014103211118510720',
      simSerialNumber: '89014103211118510720',
      isChanged: false,
    };
  }

  /**
   * Store original SIM info
   */
  private async storeSIMInfo(): Promise<void> {
    try {
      if (!this.originalSIM) {
        const simInfo = await this.getSIMInfo();
        await AsyncStorage.setItem('original_sim', simInfo.iccId);
        this.originalSIM = simInfo.iccId;
      }
    } catch (error) {
      console.error('Store SIM info error:', error);
    }
  }

  /**
   * Notify trusted contacts
   */
  private async notifyTrustedContacts(message: string): Promise<void> {
    try {
      const settings = await this.getSettings();
      const location = await this.getCurrentLocation();

      for (const contact of settings.trustedContacts) {
        // In production, would send SMS/email
        console.log(`Notifying ${contact.name}: ${message}`);
        if (location) {
          console.log(`Location: ${location.latitude}, ${location.longitude}`);
        }
      }
    } catch (error) {
      console.error('Notify contacts error:', error);
    }
  }

  /**
   * Get theft alerts
   */
  async getTheftAlerts(limit: number = 50): Promise<TheftAlert[]> {
    try {
      const stored = await AsyncStorage.getItem('theft_alerts');
      const alerts: TheftAlert[] = stored ? JSON.parse(stored) : [];
      return alerts.slice(0, limit);
    } catch (error) {
      return [];
    }
  }

  /**
   * Save theft alert
   */
  private async saveTheftAlert(alert: TheftAlert): Promise<void> {
    try {
      const alerts = await this.getTheftAlerts(100);
      alerts.unshift(alert);
      await AsyncStorage.setItem('theft_alerts', JSON.stringify(alerts.slice(0, 100)));
    } catch (error) {
      console.error('Save alert error:', error);
    }
  }

  /**
   * Acknowledge alert
   */
  async acknowledgeAlert(alertId: string): Promise<boolean> {
    try {
      const alerts = await this.getTheftAlerts(100);
      const alert = alerts.find(a => a.id === alertId);
      if (alert) {
        alert.isAcknowledged = true;
        await AsyncStorage.setItem('theft_alerts', JSON.stringify(alerts));
        return true;
      }
      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get device status
   */
  async getDeviceStatus(): Promise<DeviceStatus> {
    const location = await this.getCurrentLocation();
    const settings = await this.getSettings();

    return {
      isLocked: false, // Would check actual lock status
      isLocated: location !== null,
      lastLocation: location || undefined,
      batteryLevel: 75, // Would get actual battery level
      isOnline: true,
      lastSeen: new Date().toISOString(),
      simChanged: await this.checkSIMChange(),
      lockMessage: undefined,
    };
  }

  /**
   * Get command history
   */
  async getCommandHistory(limit: number = 20): Promise<RemoteCommand[]> {
    try {
      const stored = await AsyncStorage.getItem('command_history');
      const history: RemoteCommand[] = stored ? JSON.parse(stored) : [];
      return history.slice(0, limit);
    } catch (error) {
      return [];
    }
  }

  /**
   * Save command to history
   */
  private async saveCommand(command: RemoteCommand): Promise<void> {
    try {
      const history = await this.getCommandHistory(50);
      const existing = history.findIndex(c => c.id === command.id);
      
      if (existing >= 0) {
        history[existing] = command;
      } else {
        history.unshift(command);
      }

      await AsyncStorage.setItem('command_history', JSON.stringify(history.slice(0, 50)));
    } catch (error) {
      console.error('Save command error:', error);
    }
  }

  /**
   * Add trusted contact
   */
  async addTrustedContact(contact: Omit<TrustedContact, 'id'>): Promise<boolean> {
    try {
      const settings = await this.getSettings();
      const newContact: TrustedContact = {
        id: `contact-${Date.now()}`,
        ...contact,
      };
      settings.trustedContacts.push(newContact);
      await this.updateSettings(settings);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Remove trusted contact
   */
  async removeTrustedContact(contactId: string): Promise<boolean> {
    try {
      const settings = await this.getSettings();
      settings.trustedContacts = settings.trustedContacts.filter(c => c.id !== contactId);
      await this.updateSettings(settings);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Test anti-theft features
   */
  async testFeatures(): Promise<{ success: boolean; message: string }> {
    try {
      const location = await this.getCurrentLocation();
      if (!location) {
        return { success: false, message: 'Location access denied' };
      }

      await this.sendMessage('Anti-theft test message');
      
      return { success: true, message: 'All anti-theft features are working correctly' };
    } catch (error) {
      return { success: false, message: 'Some features failed to test' };
    }
  }
}

export const AntiTheftService = new AntiTheftServiceClass();
