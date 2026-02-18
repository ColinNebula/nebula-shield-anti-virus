/**
 * Nebula Shield - Mobile Companion App
 * React Native Application for Remote Monitoring and Control
 * 
 * Features:
 * - Real-time device monitoring
 * - Remote scan control
 * - Threat alerts and notifications
 * - Quarantine management
 * - Protection status overview
 */

import React, { useState, useEffect } from 'react';
import {
  StyleSheet,
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  RefreshControl,
  Alert,
  Switch,
  Platform,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import PushNotification from 'react-native-push-notification';
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';

// API Configuration
const API_BASE_URL = __DEV__ 
  ? 'http://localhost:8080/api' 
  : 'https://api.nebulashield.com/api';

// API Service
class NebulaShieldAPI {
  constructor() {
    this.baseURL = API_BASE_URL;
    this.token = null;
  }

  async setAuthToken(token) {
    this.token = token;
    await AsyncStorage.setItem('auth_token', token);
  }

  async getAuthToken() {
    if (!this.token) {
      this.token = await AsyncStorage.getItem('auth_token');
    }
    return this.token;
  }

  async request(endpoint, options = {}) {
    const token = await this.getAuthToken();
    const headers = {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` }),
      ...options.headers,
    };

    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        ...options,
        headers,
      });

      if (!response.ok) {
        throw new Error(`API Error: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('API Request Failed:', error);
      throw error;
    }
  }

  // Device Management
  async getDevices() {
    return this.request('/mobile/devices');
  }

  async getDeviceStatus(deviceId) {
    return this.request(`/mobile/devices/${deviceId}/status`);
  }

  async pairDevice(pairingCode) {
    return this.request('/mobile/devices/pair', {
      method: 'POST',
      body: JSON.stringify({ pairingCode }),
    });
  }

  // Scan Control
  async startScan(deviceId, scanType = 'quick') {
    return this.request(`/mobile/devices/${deviceId}/scan`, {
      method: 'POST',
      body: JSON.stringify({ scanType }),
    });
  }

  async getScanStatus(deviceId) {
    return this.request(`/mobile/devices/${deviceId}/scan/status`);
  }

  async stopScan(deviceId) {
    return this.request(`/mobile/devices/${deviceId}/scan`, {
      method: 'DELETE',
    });
  }

  // Threat Management
  async getThreats(deviceId) {
    return this.request(`/mobile/devices/${deviceId}/threats`);
  }

  async quarantineThreat(deviceId, threatId) {
    return this.request(`/mobile/devices/${deviceId}/threats/${threatId}/quarantine`, {
      method: 'POST',
    });
  }

  // Settings
  async getSettings(deviceId) {
    return this.request(`/mobile/devices/${deviceId}/settings`);
  }

  async updateSettings(deviceId, settings) {
    return this.request(`/mobile/devices/${deviceId}/settings`, {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  }

  // Statistics
  async getStatistics(deviceId) {
    return this.request(`/mobile/devices/${deviceId}/statistics`);
  }
}

const api = new NebulaShieldAPI();

// Dashboard Screen
function DashboardScreen({ navigation }) {
  const [devices, setDevices] = useState([]);
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDevices();
    setupNotifications();
  }, []);

  const setupNotifications = () => {
    PushNotification.configure({
      onNotification: function (notification) {
        console.log('NOTIFICATION:', notification);
      },
      permissions: {
        alert: true,
        badge: true,
        sound: true,
      },
      popInitialNotification: true,
      requestPermissions: true,
    });
  };

  const loadDevices = async () => {
    try {
      setLoading(true);
      const devicesData = await api.getDevices();
      setDevices(devicesData.devices || []);
    } catch (error) {
      Alert.alert('Error', 'Failed to load devices');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const onRefresh = () => {
    setRefreshing(true);
    loadDevices();
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'protected': return '#4CAF50';
      case 'warning': return '#FFC107';
      case 'danger': return '#F44336';
      default: return '#9E9E9E';
    }
  };

  const renderDevice = (device) => (
    <TouchableOpacity
      key={device.id}
      style={styles.deviceCard}
      onPress={() => navigation.navigate('DeviceDetails', { device })}
    >
      <View style={styles.deviceHeader}>
        <Icon 
          name={device.platform === 'windows' ? 'laptop' : device.platform === 'macos' ? 'apple' : 'linux'}
          size={32}
          color="#2196F3"
        />
        <View style={styles.deviceInfo}>
          <Text style={styles.deviceName}>{device.name}</Text>
          <Text style={styles.devicePlatform}>{device.platform}</Text>
        </View>
        <View style={[styles.statusIndicator, { backgroundColor: getStatusColor(device.status) }]} />
      </View>
      
      <View style={styles.deviceStats}>
        <View style={styles.stat}>
          <Icon name="shield-check" size={20} color="#4CAF50" />
          <Text style={styles.statText}>{device.filesScanned || 0} scanned</Text>
        </View>
        <View style={styles.stat}>
          <Icon name="alert" size={20} color="#F44336" />
          <Text style={styles.statText}>{device.threatsBlocked || 0} blocked</Text>
        </View>
      </View>
    </TouchableOpacity>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>🛡️ Nebula Shield</Text>
        <TouchableOpacity onPress={() => navigation.navigate('AddDevice')}>
          <Icon name="plus-circle" size={28} color="#2196F3" />
        </TouchableOpacity>
      </View>

      <ScrollView
        style={styles.content}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
        }
      >
        {loading ? (
          <Text style={styles.loadingText}>Loading devices...</Text>
        ) : devices.length === 0 ? (
          <View style={styles.emptyState}>
            <Icon name="devices" size={64} color="#BDBDBD" />
            <Text style={styles.emptyStateText}>No devices paired</Text>
            <TouchableOpacity 
              style={styles.addButton}
              onPress={() => navigation.navigate('AddDevice')}
            >
              <Text style={styles.addButtonText}>Add Device</Text>
            </TouchableOpacity>
          </View>
        ) : (
          devices.map(renderDevice)
        )}
      </ScrollView>
    </View>
  );
}

// Device Details Screen
function DeviceDetailsScreen({ route, navigation }) {
  const { device } = route.params;
  const [status, setStatus] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadDeviceStatus();
    const interval = setInterval(loadDeviceStatus, 5000); // Poll every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const loadDeviceStatus = async () => {
    try {
      const statusData = await api.getDeviceStatus(device.id);
      setStatus(statusData);
      setScanning(statusData.scanning || false);
    } catch (error) {
      console.error('Failed to load device status:', error);
    } finally {
      setRefreshing(false);
    }
  };

  const startScan = async (scanType) => {
    try {
      await api.startScan(device.id, scanType);
      setScanning(true);
      Alert.alert('Success', `${scanType} scan started`);
      loadDeviceStatus();
    } catch (error) {
      Alert.alert('Error', 'Failed to start scan');
    }
  };

  const stopScan = async () => {
    try {
      await api.stopScan(device.id);
      setScanning(false);
      Alert.alert('Success', 'Scan stopped');
      loadDeviceStatus();
    } catch (error) {
      Alert.alert('Error', 'Failed to stop scan');
    }
  };

  return (
    <ScrollView 
      style={styles.container}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={() => {
          setRefreshing(true);
          loadDeviceStatus();
        }} />
      }
    >
      <View style={styles.detailsHeader}>
        <Icon 
          name={device.platform === 'windows' ? 'laptop' : device.platform === 'macos' ? 'apple' : 'linux'}
          size={48}
          color="#2196F3"
        />
        <Text style={styles.detailsTitle}>{device.name}</Text>
        <Text style={styles.detailsSubtitle}>{device.platform}</Text>
      </View>

      {status && (
        <>
          <View style={styles.protectionCard}>
            <Text style={styles.cardTitle}>Protection Status</Text>
            <View style={styles.protectionStatus}>
              <Icon 
                name={status.protected ? "shield-check" : "shield-alert"}
                size={48}
                color={status.protected ? "#4CAF50" : "#F44336"}
              />
              <Text style={[styles.protectionText, { color: status.protected ? "#4CAF50" : "#F44336" }]}>
                {status.protected ? "Protected" : "At Risk"}
              </Text>
            </View>
          </View>

          <View style={styles.card}>
            <Text style={styles.cardTitle}>Quick Actions</Text>
            <View style={styles.actionButtons}>
              {!scanning ? (
                <>
                  <TouchableOpacity 
                    style={[styles.actionButton, styles.primaryButton]}
                    onPress={() => startScan('quick')}
                  >
                    <Icon name="flash" size={24} color="#FFF" />
                    <Text style={styles.actionButtonText}>Quick Scan</Text>
                  </TouchableOpacity>
                  <TouchableOpacity 
                    style={[styles.actionButton, styles.secondaryButton]}
                    onPress={() => startScan('full')}
                  >
                    <Icon name="shield-search" size={24} color="#2196F3" />
                    <Text style={[styles.actionButtonText, { color: '#2196F3' }]}>Full Scan</Text>
                  </TouchableOpacity>
                </>
              ) : (
                <TouchableOpacity 
                  style={[styles.actionButton, styles.dangerButton]}
                  onPress={stopScan}
                >
                  <Icon name="stop" size={24} color="#FFF" />
                  <Text style={styles.actionButtonText}>Stop Scan</Text>
                </TouchableOpacity>
              )}
            </View>
          </View>

          {scanning && status.scanProgress && (
            <View style={styles.card}>
              <Text style={styles.cardTitle}>Scan Progress</Text>
              <View style={styles.progressInfo}>
                <Text style={styles.progressText}>
                  {status.scanProgress.filesScanned} / {status.scanProgress.totalFiles} files
                </Text>
                <Text style={styles.progressPercentage}>
                  {Math.round(status.scanProgress.progress)}%
                </Text>
              </View>
              <View style={styles.progressBar}>
                <View 
                  style={[styles.progressFill, { width: `${status.scanProgress.progress}%` }]}
                />
              </View>
            </View>
          )}

          <View style={styles.card}>
            <Text style={styles.cardTitle}>Statistics</Text>
            <View style={styles.statsGrid}>
              <View style={styles.statItem}>
                <Icon name="file-check" size={32} color="#4CAF50" />
                <Text style={styles.statValue}>{status.statistics?.filesScanned || 0}</Text>
                <Text style={styles.statLabel}>Files Scanned</Text>
              </View>
              <View style={styles.statItem}>
                <Icon name="shield-alert" size={32} color="#F44336" />
                <Text style={styles.statValue}>{status.statistics?.threatsBlocked || 0}</Text>
                <Text style={styles.statLabel}>Threats Blocked</Text>
              </View>
              <View style={styles.statItem}>
                <Icon name="lock" size={32} color="#FFC107" />
                <Text style={styles.statValue}>{status.statistics?.quarantined || 0}</Text>
                <Text style={styles.statLabel}>Quarantined</Text>
              </View>
              <View style={styles.statItem}>
                <Icon name="update" size={32} color="#2196F3" />
                <Text style={styles.statValue}>
                  {status.lastUpdate ? new Date(status.lastUpdate).toLocaleDateString() : 'N/A'}
                </Text>
                <Text style={styles.statLabel}>Last Update</Text>
              </View>
            </View>
          </View>
        </>
      )}
    </ScrollView>
  );
}

// Threats Screen
function ThreatsScreen({ navigation }) {
  const [threats, setThreats] = useState([]);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);

  useEffect(() => {
    loadThreats();
  }, [selectedDevice]);

  const loadThreats = async () => {
    if (!selectedDevice) return;
    
    try {
      const threatsData = await api.getThreats(selectedDevice.id);
      setThreats(threatsData.threats || []);
    } catch (error) {
      Alert.alert('Error', 'Failed to load threats');
    } finally {
      setRefreshing(false);
    }
  };

  const quarantineThreat = async (threatId) => {
    try {
      await api.quarantineThreat(selectedDevice.id, threatId);
      Alert.alert('Success', 'Threat quarantined');
      loadThreats();
    } catch (error) {
      Alert.alert('Error', 'Failed to quarantine threat');
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return '#F44336';
      case 'high': return '#FF5722';
      case 'medium': return '#FFC107';
      case 'low': return '#4CAF50';
      default: return '#9E9E9E';
    }
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Detected Threats</Text>
      </View>

      <ScrollView
        style={styles.content}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={() => {
            setRefreshing(true);
            loadThreats();
          }} />
        }
      >
        {threats.map((threat) => (
          <View key={threat.id} style={styles.threatCard}>
            <View style={styles.threatHeader}>
              <Icon name="alert-circle" size={24} color={getSeverityColor(threat.severity)} />
              <View style={styles.threatInfo}>
                <Text style={styles.threatName}>{threat.name}</Text>
                <Text style={styles.threatPath}>{threat.path}</Text>
              </View>
            </View>
            
            <View style={styles.threatDetails}>
              <Text style={styles.threatType}>Type: {threat.type}</Text>
              <Text style={[styles.threatSeverity, { color: getSeverityColor(threat.severity) }]}>
                {threat.severity.toUpperCase()}
              </Text>
            </View>

            <View style={styles.threatActions}>
              <TouchableOpacity 
                style={styles.quarantineButton}
                onPress={() => quarantineThreat(threat.id)}
              >
                <Text style={styles.quarantineButtonText}>Quarantine</Text>
              </TouchableOpacity>
            </View>
          </View>
        ))}

        {threats.length === 0 && (
          <View style={styles.emptyState}>
            <Icon name="shield-check" size={64} color="#4CAF50" />
            <Text style={styles.emptyStateText}>No threats detected</Text>
          </View>
        )}
      </ScrollView>
    </View>
  );
}

// Settings Screen
function SettingsScreen() {
  const [settings, setSettings] = useState({
    realTimeProtection: true,
    cloudSync: true,
    notifications: true,
    autoUpdate: true,
  });

  const toggleSetting = (key) => {
    setSettings(prev => ({
      ...prev,
      [key]: !prev[key],
    }));
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Settings</Text>
      </View>

      <View style={styles.settingsSection}>
        <Text style={styles.sectionTitle}>Protection</Text>
        
        <View style={styles.settingItem}>
          <View style={styles.settingInfo}>
            <Icon name="shield" size={24} color="#2196F3" />
            <Text style={styles.settingLabel}>Real-Time Protection</Text>
          </View>
          <Switch
            value={settings.realTimeProtection}
            onValueChange={() => toggleSetting('realTimeProtection')}
          />
        </View>

        <View style={styles.settingItem}>
          <View style={styles.settingInfo}>
            <Icon name="cloud-sync" size={24} color="#2196F3" />
            <Text style={styles.settingLabel}>Cloud Sync</Text>
          </View>
          <Switch
            value={settings.cloudSync}
            onValueChange={() => toggleSetting('cloudSync')}
          />
        </View>
      </View>

      <View style={styles.settingsSection}>
        <Text style={styles.sectionTitle}>Notifications</Text>
        
        <View style={styles.settingItem}>
          <View style={styles.settingInfo}>
            <Icon name="bell" size={24} color="#2196F3" />
            <Text style={styles.settingLabel}>Push Notifications</Text>
          </View>
          <Switch
            value={settings.notifications}
            onValueChange={() => toggleSetting('notifications')}
          />
        </View>
      </View>

      <View style={styles.settingsSection}>
        <Text style={styles.sectionTitle}>Updates</Text>
        
        <View style={styles.settingItem}>
          <View style={styles.settingInfo}>
            <Icon name="update" size={24} color="#2196F3" />
            <Text style={styles.settingLabel}>Auto Update</Text>
          </View>
          <Switch
            value={settings.autoUpdate}
            onValueChange={() => toggleSetting('autoUpdate')}
          />
        </View>
      </View>

      <TouchableOpacity style={styles.aboutButton}>
        <Icon name="information" size={24} color="#2196F3" />
        <Text style={styles.aboutButtonText}>About Nebula Shield</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

// Navigation Setup
const Tab = createBottomTabNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Tab.Navigator
        screenOptions={({ route }) => ({
          headerShown: false,
          tabBarIcon: ({ focused, color, size }) => {
            let iconName;

            if (route.name === 'Dashboard') {
              iconName = 'view-dashboard';
            } else if (route.name === 'Threats') {
              iconName = 'alert-circle';
            } else if (route.name === 'Settings') {
              iconName = 'cog';
            }

            return <Icon name={iconName} size={size} color={color} />;
          },
          tabBarActiveTintColor: '#2196F3',
          tabBarInactiveTintColor: '#9E9E9E',
        })}
      >
        <Tab.Screen name="Dashboard" component={DashboardScreen} />
        <Tab.Screen name="Threats" component={ThreatsScreen} />
        <Tab.Screen name="Settings" component={SettingsScreen} />
      </Tab.Navigator>
    </NavigationContainer>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F5F5F5',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 20,
    backgroundColor: '#FFF',
    borderBottomWidth: 1,
    borderBottomColor: '#E0E0E0',
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#212121',
  },
  content: {
    flex: 1,
    padding: 16,
  },
  deviceCard: {
    backgroundColor: '#FFF',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
    elevation: 2,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
  },
  deviceHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 12,
  },
  deviceInfo: {
    flex: 1,
    marginLeft: 12,
  },
  deviceName: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#212121',
  },
  devicePlatform: {
    fontSize: 14,
    color: '#757575',
    marginTop: 4,
  },
  statusIndicator: {
    width: 12,
    height: 12,
    borderRadius: 6,
  },
  deviceStats: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    paddingTop: 12,
    borderTopWidth: 1,
    borderTopColor: '#E0E0E0',
  },
  stat: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  statText: {
    marginLeft: 8,
    fontSize: 14,
    color: '#757575',
  },
  emptyState: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 64,
  },
  emptyStateText: {
    fontSize: 18,
    color: '#9E9E9E',
    marginTop: 16,
  },
  addButton: {
    marginTop: 24,
    backgroundColor: '#2196F3',
    paddingHorizontal: 32,
    paddingVertical: 12,
    borderRadius: 8,
  },
  addButtonText: {
    color: '#FFF',
    fontSize: 16,
    fontWeight: 'bold',
  },
  loadingText: {
    textAlign: 'center',
    fontSize: 16,
    color: '#757575',
    marginTop: 32,
  },
  detailsHeader: {
    alignItems: 'center',
    padding: 32,
    backgroundColor: '#FFF',
  },
  detailsTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#212121',
    marginTop: 16,
  },
  detailsSubtitle: {
    fontSize: 16,
    color: '#757575',
    marginTop: 4,
  },
  card: {
    backgroundColor: '#FFF',
    borderRadius: 12,
    padding: 16,
    marginHorizontal: 16,
    marginBottom: 16,
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#212121',
    marginBottom: 16,
  },
  protectionCard: {
    backgroundColor: '#FFF',
    borderRadius: 12,
    padding: 24,
    marginHorizontal: 16,
    marginBottom: 16,
    alignItems: 'center',
  },
  protectionStatus: {
    alignItems: 'center',
  },
  protectionText: {
    fontSize: 24,
    fontWeight: 'bold',
    marginTop: 12,
  },
  actionButtons: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  actionButton: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 16,
    borderRadius: 8,
    marginHorizontal: 4,
  },
  primaryButton: {
    backgroundColor: '#2196F3',
  },
  secondaryButton: {
    backgroundColor: '#FFF',
    borderWidth: 2,
    borderColor: '#2196F3',
  },
  dangerButton: {
    backgroundColor: '#F44336',
  },
  actionButtonText: {
    color: '#FFF',
    fontSize: 16,
    fontWeight: 'bold',
    marginLeft: 8,
  },
  progressInfo: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 8,
  },
  progressText: {
    fontSize: 14,
    color: '#757575',
  },
  progressPercentage: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#2196F3',
  },
  progressBar: {
    height: 8,
    backgroundColor: '#E0E0E0',
    borderRadius: 4,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#2196F3',
  },
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
  },
  statItem: {
    width: '48%',
    alignItems: 'center',
    padding: 16,
    marginBottom: 16,
    backgroundColor: '#F5F5F5',
    borderRadius: 8,
  },
  statValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#212121',
    marginTop: 8,
  },
  statLabel: {
    fontSize: 12,
    color: '#757575',
    marginTop: 4,
    textAlign: 'center',
  },
  threatCard: {
    backgroundColor: '#FFF',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
  },
  threatHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 12,
  },
  threatInfo: {
    flex: 1,
    marginLeft: 12,
  },
  threatName: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#212121',
  },
  threatPath: {
    fontSize: 12,
    color: '#757575',
    marginTop: 4,
  },
  threatDetails: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  threatType: {
    fontSize: 14,
    color: '#757575',
  },
  threatSeverity: {
    fontSize: 14,
    fontWeight: 'bold',
  },
  threatActions: {
    borderTopWidth: 1,
    borderTopColor: '#E0E0E0',
    paddingTop: 12,
  },
  quarantineButton: {
    backgroundColor: '#F44336',
    padding: 12,
    borderRadius: 8,
    alignItems: 'center',
  },
  quarantineButtonText: {
    color: '#FFF',
    fontSize: 14,
    fontWeight: 'bold',
  },
  settingsSection: {
    backgroundColor: '#FFF',
    marginBottom: 16,
    padding: 16,
  },
  sectionTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#757575',
    marginBottom: 16,
    textTransform: 'uppercase',
  },
  settingItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
  },
  settingInfo: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  settingLabel: {
    fontSize: 16,
    color: '#212121',
    marginLeft: 16,
  },
  aboutButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#FFF',
    padding: 16,
    marginBottom: 32,
  },
  aboutButtonText: {
    fontSize: 16,
    color: '#2196F3',
    marginLeft: 12,
  },
});
