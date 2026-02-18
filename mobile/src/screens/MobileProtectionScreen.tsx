import React, {useEffect, useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  TextInput,
  Alert,
  Platform,
} from 'react-native';
import {
  Card,
  Button,
  ProgressBar,
  Chip,
  useTheme,
  Divider,
  List,
  Surface,
  SegmentedButtons,
} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import {DeviceHealthService, DeviceHealthData} from '../services/DeviceHealthService';
import {WebProtectionService, URLCheckResult} from '../services/WebProtectionService';
import {WiFiSecurityService, WiFiSecurityScan} from '../services/WiFiSecurityService';
import {PrivacyAuditService, PermissionUsage, PrivacyScore} from '../services/PrivacyAuditService';
import {NetworkTrafficService, NetworkConnection, TrafficStats} from '../services/NetworkTrafficService';

const MobileProtectionScreen = () => {
  const theme = useTheme();
  const [refreshing, setRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [deviceHealth, setDeviceHealth] = useState<DeviceHealthData | null>(null);
  const [recommendations, setRecommendations] = useState<string[]>([]);
  const [urlToCheck, setUrlToCheck] = useState('');
  const [urlCheckResult, setUrlCheckResult] = useState<URLCheckResult | null>(null);
  const [isCheckingURL, setIsCheckingURL] = useState(false);
  
  // WiFi Security
  const [wifiScan, setWifiScan] = useState<WiFiSecurityScan | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  
  // Privacy Audit
  const [privacyScore, setPrivacyScore] = useState<PrivacyScore | null>(null);
  const [permissionActivity, setPermissionActivity] = useState<PermissionUsage[]>([]);
  
  // Network Traffic
  const [networkConnections, setNetworkConnections] = useState<NetworkConnection[]>([]);
  const [trafficStats, setTrafficStats] = useState<TrafficStats | null>(null);
  const [suspiciousActivities, setSuspiciousActivities] = useState<any[]>([]);

  useEffect(() => {
    loadDeviceHealth();
    loadPrivacyData();
    loadNetworkData();
  }, []);
  
  useEffect(() => {
    if (activeTab === 'wifi') {
      handleWiFiScan();
    } else if (activeTab === 'traffic') {
      loadNetworkData();
      NetworkTrafficService.startMonitoring((data) => {
        setNetworkConnections(data.connections);
        setTrafficStats(data.stats);
      });
      return () => NetworkTrafficService.stopMonitoring();
    }
  }, [activeTab]);

  const loadDeviceHealth = async () => {
    try {
      const health = await DeviceHealthService.getDeviceHealth();
      const recs = await DeviceHealthService.getSecurityRecommendations();
      setDeviceHealth(health);
      setRecommendations(recs);
    } catch (error) {
      console.error('Error loading device health:', error);
      Alert.alert('Error', 'Failed to load device health data');
    }
  };
  
  const loadPrivacyData = async () => {
    try {
      const [score, activity] = await Promise.all([
        PrivacyAuditService.getPrivacyScore(),
        PrivacyAuditService.getTodayActivity(),
      ]);
      setPrivacyScore(score);
      setPermissionActivity(activity);
    } catch (error) {
      console.error('Error loading privacy data:', error);
    }
  };
  
  const loadNetworkData = async () => {
    try {
      const [connections, stats, activities] = await Promise.all([
        NetworkTrafficService.getActiveConnections(),
        NetworkTrafficService.getTrafficStats(),
        NetworkTrafficService.getSuspiciousActivities(),
      ]);
      setNetworkConnections(connections);
      setTrafficStats(stats);
      setSuspiciousActivities(activities);
    } catch (error) {
      console.error('Error loading network data:', error);
    }
  };
  
  const handleWiFiScan = async () => {
    console.log('🔍 handleWiFiScan called');
    setIsScanning(true);
    console.log('Starting WiFi scan...');
    try {
      const scan = await WiFiSecurityService.scanWiFiNetworks();
      console.log('WiFi scan completed:', scan);
      
      if (scan) {
        setWifiScan(scan);
        Alert.alert(
          '✅ Scan Complete',
          `Found ${scan.totalNetworks} networks\n${scan.secureNetworks} secure, ${scan.insecureNetworks} insecure`,
          [{text: 'OK'}]
        );
      } else {
        Alert.alert('No Data', 'WiFi scan returned no data. Using fallback.');
      }
    } catch (error) {
      console.error('WiFi scan error:', error);
      Alert.alert(
        'Scan Failed',
        `Error: ${error instanceof Error ? error.message : 'Unknown error'}\n\nPlease check that the backend server is running.`
      );
    } finally {
      setIsScanning(false);
      console.log('🏁 WiFi scan finished, isScanning set to false');
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await Promise.all([
      loadDeviceHealth(),
      activeTab === 'wifi' ? handleWiFiScan() : Promise.resolve(),
      activeTab === 'privacy' ? loadPrivacyData() : Promise.resolve(),
      activeTab === 'traffic' ? loadNetworkData() : Promise.resolve(),
    ]);
    setRefreshing(false);
  };

  const handleCheckURL = async () => {
    if (!urlToCheck.trim()) {
      Alert.alert('Invalid URL', 'Please enter a URL to check');
      return;
    }

    setIsCheckingURL(true);
    try {
      const result = await WebProtectionService.checkURL(urlToCheck);
      setUrlCheckResult(result);
      
      if (!result.isSafe) {
        Alert.alert(
          '⚠️ Unsafe Website Detected',
          `${result.description}\n\nThreat Type: ${result.threatType}\nThreat Level: ${result.threatLevel}`,
          [{text: 'OK'}]
        );
      }
    } catch (error) {
      Alert.alert('Error', 'Failed to check URL');
    } finally {
      setIsCheckingURL(false);
    }
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return '#4caf50';
    if (score >= 60) return '#ff9800';
    return '#f44336';
  };

  const getThreatLevelColor = (level?: string) => {
    switch (level) {
      case 'critical':
        return '#d32f2f';
      case 'high':
        return '#f44336';
      case 'medium':
        return '#ff9800';
      case 'low':
        return '#ffc107';
      default:
        return '#9e9e9e';
    }
  };

  if (!deviceHealth) {
    return (
      <View style={styles.loadingContainer}>
        <Text>Loading device health...</Text>
      </View>
    );
  }

  return (
    <ScrollView
      style={[styles.container, {backgroundColor: theme.colors.background}]}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}>
      {/* Header */}
      <Surface style={styles.header}>
        <Icon name="shield-check" size={40} color={theme.colors.primary} />
        <Text style={styles.headerTitle}>Mobile Protection</Text>
        <Text style={styles.headerSubtitle}>
          {Platform.OS === 'ios' ? 'iOS' : 'Android'} Device Security
        </Text>
        {deviceHealth && (
          <View style={styles.dataSourceBadge}>
            <Icon 
              name={deviceHealth.dataSource === 'real' ? 'check-circle' : 'information'} 
              size={12} 
              color={deviceHealth.dataSource === 'real' ? '#4caf50' : '#ff9800'} 
            />
            <Text style={styles.dataSourceText}>
              {deviceHealth.dataSource === 'real' ? 'Real Device Data' : 'Simulated Data'}
            </Text>
          </View>
        )}
      </Surface>

      {/* Tab Selection */}
      <View style={styles.tabContainer}>
        <SegmentedButtons
          value={activeTab}
          onValueChange={setActiveTab}
          buttons={[
            {value: 'overview', label: 'Overview', icon: 'shield-check'},
            {value: 'wifi', label: 'WiFi', icon: 'wifi'},
            {value: 'privacy', label: 'Privacy', icon: 'eye-off'},
            {value: 'traffic', label: 'Traffic', icon: 'wan'},
          ]}
          style={styles.segmentedButtons}
        />
      </View>

      {/* Render Tab Content */}
      {activeTab === 'overview' && renderOverviewTab()}
      {activeTab === 'wifi' && renderWiFiTab()}
      {activeTab === 'privacy' && renderPrivacyTab()}
      {activeTab === 'traffic' && renderTrafficTab()}
    </ScrollView>
  );

  function renderOverviewTab() {
    if (!deviceHealth) return null;
    
    return (
      <>
      {/* Data Source Indicator */}
      {deviceHealth.dataSource === 'mock' && (
        <Card style={[styles.card, { backgroundColor: '#FFF3E0' }]}>
          <Card.Content>
            <View style={{ flexDirection: 'row', alignItems: 'center' }}>
              <Icon name="information" size={24} color="#FF9800" />
              <View style={{ marginLeft: 12, flex: 1 }}>
                <Text style={{ fontSize: 14, fontWeight: '600', color: '#E65100' }}>
                  Using Simulated Data
                </Text>
                <Text style={{ fontSize: 12, color: '#666', marginTop: 4 }}>
                  Running in Expo Go. Build a standalone app to get real device data.
                </Text>
              </View>
            </View>
          </Card.Content>
        </Card>
      )}
      
      {deviceHealth.dataSource === 'real' && (
        <Card style={[styles.card, { backgroundColor: '#E8F5E9' }]}>
          <Card.Content>
            <View style={{ flexDirection: 'row', alignItems: 'center' }}>
              <Icon name="check-circle" size={24} color="#4CAF50" />
              <View style={{ marginLeft: 12, flex: 1 }}>
                <Text style={{ fontSize: 14, fontWeight: '600', color: '#2E7D32' }}>
                  ✅ Real Device Data Active
                </Text>
                <Text style={{ fontSize: 12, color: '#666', marginTop: 4 }}>
                  All metrics are from your actual device hardware
                </Text>
              </View>
            </View>
          </Card.Content>
        </Card>
      )}
      
      {/* Security Score */}
      <Card style={styles.card}>
        <Card.Content>
          <View style={styles.scoreContainer}>
            <View style={styles.scoreCircle}>
              <Text
                style={[
                  styles.scoreText,
                  {color: getSecurityScoreColor(deviceHealth.security.securityScore)},
                ]}>
                {deviceHealth.security.securityScore}
              </Text>
              <Text style={styles.scoreLabel}>Security Score</Text>
            </View>
            <View style={styles.scoreDetails}>
              {deviceHealth.security.isJailbroken && (
                <Chip icon="alert" style={styles.warningChip}>
                  iOS Jailbroken
                </Chip>
              )}
              {deviceHealth.security.isRooted && (
                <Chip icon="alert" style={styles.warningChip}>
                  Android Rooted
                </Chip>
              )}
              {deviceHealth.security.isEmulator && (
                <Chip icon="information" style={styles.infoChip}>
                  Running in Emulator
                </Chip>
              )}
              {deviceHealth.security.isPinOrFingerprintSet ? (
                <Chip icon="lock" style={styles.successChip}>
                  Device Locked
                </Chip>
              ) : (
                <Chip icon="lock-open" style={styles.warningChip}>
                  No Device Lock
                </Chip>
              )}
            </View>
          </View>
        </Card.Content>
      </Card>

      {/* Security Recommendations */}
      <Card style={styles.card}>
        <Card.Title
          title="Security Recommendations"
          left={props => <Icon name="lightbulb-on" {...props} />}
        />
        <Card.Content>
          {recommendations.map((rec, index) => (
            <View key={index} style={styles.recommendationItem}>
              <Text style={styles.recommendationText}>{rec}</Text>
            </View>
          ))}
        </Card.Content>
      </Card>

      {/* Device Performance */}
      <Card style={styles.card}>
        <Card.Title
          title="Device Performance"
          left={props => <Icon name="speedometer" {...props} />}
        />
        <Card.Content>
          <View style={styles.metricRow}>
            <Icon name="battery" size={24} color={theme.colors.primary} />
            <Text style={styles.metricLabel}>Battery</Text>
            <Text style={styles.metricValue}>
              {deviceHealth.performance.batteryLevel}%
              {deviceHealth.performance.isCharging && ' (Charging)'}
            </Text>
          </View>

          <View style={styles.metricRow}>
            <Icon name="memory" size={24} color={theme.colors.primary} />
            <Text style={styles.metricLabel}>RAM</Text>
            <Text style={styles.metricValue}>{deviceHealth.performance.totalMemory} GB</Text>
          </View>

          <View style={styles.metricRow}>
            <Icon name="harddisk" size={24} color={theme.colors.primary} />
            <Text style={styles.metricLabel}>Storage</Text>
            <Text style={styles.metricValue}>
              {deviceHealth.performance.freeStorage} GB / {deviceHealth.performance.totalStorage}{' '}
              GB free
            </Text>
          </View>

          <ProgressBar
            progress={deviceHealth.performance.storageUsagePercent / 100}
            color={
              deviceHealth.performance.storageUsagePercent > 90
                ? '#f44336'
                : theme.colors.primary
            }
            style={styles.progressBar}
          />
          <Text style={styles.storageText}>
            {deviceHealth.performance.storageUsagePercent}% Used
          </Text>
        </Card.Content>
      </Card>

      {/* Network Status */}
      <Card style={styles.card}>
        <Card.Title title="Network Status" left={props => <Icon name="wifi" {...props} />} />
        <Card.Content>
          <View style={styles.metricRow}>
            <Icon
              name={deviceHealth.network.isConnected ? 'wifi' : 'wifi-off'}
              size={24}
              color={deviceHealth.network.isConnected ? '#4caf50' : '#f44336'}
            />
            <Text style={styles.metricLabel}>Connection</Text>
            <Text style={styles.metricValue}>
              {deviceHealth.network.isConnected ? 'Connected' : 'Disconnected'}
            </Text>
          </View>

          <View style={styles.metricRow}>
            <Icon name="access-point-network" size={24} color={theme.colors.primary} />
            <Text style={styles.metricLabel}>Type</Text>
            <Text style={styles.metricValue}>
              {deviceHealth.network.type.toUpperCase()}
            </Text>
          </View>

          <View style={styles.metricRow}>
            <Icon
              name="shield-lock"
              size={24}
              color={deviceHealth.network.isVpnActive ? '#4caf50' : '#ff9800'}
            />
            <Text style={styles.metricLabel}>VPN</Text>
            <Text style={styles.metricValue}>
              {deviceHealth.network.isVpnActive ? 'Active' : 'Not Active'}
            </Text>
          </View>
        </Card.Content>
      </Card>

      {/* URL Checker */}
      <Card style={styles.card}>
        <Card.Title
          title="Safe Browsing Checker"
          subtitle="Check if a website is safe before visiting"
          left={props => <Icon name="web" {...props} />}
        />
        <Card.Content>
          <TextInput
            style={styles.urlInput}
            placeholder="Enter URL (e.g., https://example.com)"
            value={urlToCheck}
            onChangeText={setUrlToCheck}
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="url"
          />

          <Button
            mode="contained"
            onPress={handleCheckURL}
            loading={isCheckingURL}
            disabled={isCheckingURL}
            style={styles.checkButton}>
            Check URL Safety
          </Button>

          {urlCheckResult && (
            <View style={styles.urlResultContainer}>
              <View
                style={[
                  styles.urlResultHeader,
                  {
                    backgroundColor: urlCheckResult.isSafe
                      ? 'rgba(76, 175, 80, 0.1)'
                      : 'rgba(244, 67, 54, 0.1)',
                  },
                ]}>
                <Icon
                  name={urlCheckResult.isSafe ? 'shield-check' : 'shield-alert'}
                  size={32}
                  color={urlCheckResult.isSafe ? '#4caf50' : '#f44336'}
                />
                <Text
                  style={[
                    styles.urlResultTitle,
                    {color: urlCheckResult.isSafe ? '#4caf50' : '#f44336'},
                  ]}>
                  {urlCheckResult.isSafe ? '✓ Safe to Visit' : '✗ Unsafe Website'}
                </Text>
              </View>

              {!urlCheckResult.isSafe && (
                <View style={styles.threatDetails}>
                  <View style={styles.threatRow}>
                    <Text style={styles.threatLabel}>Threat Type:</Text>
                    <Chip
                      style={{
                        backgroundColor: getThreatLevelColor(urlCheckResult.threatLevel),
                      }}
                      textStyle={{color: '#fff'}}>
                      {urlCheckResult.threatType?.toUpperCase()}
                    </Chip>
                  </View>

                  <View style={styles.threatRow}>
                    <Text style={styles.threatLabel}>Threat Level:</Text>
                    <Chip
                      style={{
                        backgroundColor: getThreatLevelColor(urlCheckResult.threatLevel),
                      }}
                      textStyle={{color: '#fff'}}>
                      {urlCheckResult.threatLevel?.toUpperCase()}
                    </Chip>
                  </View>

                  <Text style={styles.threatDescription}>{urlCheckResult.description}</Text>
                  <Text style={styles.threatReason}>
                    Reason: {urlCheckResult.blockedReason}
                  </Text>
                </View>
              )}
            </View>
          )}
        </Card.Content>
      </Card>

      {/* Device Info */}
      <Card style={styles.card}>
        <Card.Title title="Device Information" left={props => <Icon name="cellphone" {...props} />} />
        <Card.Content>
          <List.Item
            title="Model"
            description={`${deviceHealth.device.brand} ${deviceHealth.device.model}`}
            left={props => <List.Icon {...props} icon="cellphone" />}
          />
          <Divider />
          <List.Item
            title="Operating System"
            description={`${deviceHealth.device.platform} ${deviceHealth.device.systemVersion}`}
            left={props => <List.Icon {...props} icon="android" />}
          />
          <Divider />
          <List.Item
            title="App Version"
            description={deviceHealth.device.appVersion}
            left={props => <List.Icon {...props} icon="application" />}
          />
        </Card.Content>
      </Card>
      </>
    );
  }

  function renderWiFiTab() {
    return (
      <>
        {/* Current Network Security */}
        {wifiScan?.currentNetwork && (
          <Card style={styles.card}>
            <Card.Title 
              title="Current Network" 
              left={props => <Icon name="wifi" {...props} />} 
            />
            <Card.Content>
              <View style={styles.networkHeader}>
                <Text style={styles.networkName}>{wifiScan.currentNetwork.ssid}</Text>
                <Chip 
                  style={[styles.ratingChip, {backgroundColor: getSecurityRatingColor(wifiScan.currentNetwork.securityRating)}]}
                  textStyle={{color: '#fff'}}>
                  {wifiScan.currentNetwork.securityRating.toUpperCase()}
                </Chip>
              </View>
              
              <View style={styles.networkDetails}>
                <View style={styles.networkRow}>
                  <Text style={styles.networkLabel}>Security Score:</Text>
                  <Text style={[styles.networkValue, {color: getSecurityRatingColor(wifiScan.currentNetwork.securityRating)}]}>
                    {wifiScan.currentNetwork.securityScore}/100
                  </Text>
                </View>
                <View style={styles.networkRow}>
                  <Text style={styles.networkLabel}>Encryption:</Text>
                  <Text style={styles.networkValue}>{wifiScan.currentNetwork.encryptionType}</Text>
                </View>
                <View style={styles.networkRow}>
                  <Text style={styles.networkLabel}>Signal Strength:</Text>
                  <Text style={styles.networkValue}>{wifiScan.currentNetwork.signalStrength}/100</Text>
                </View>
                {wifiScan.currentNetwork.routerVendor && (
                  <View style={styles.networkRow}>
                    <Text style={styles.networkLabel}>Router Vendor:</Text>
                    <Text style={styles.networkValue}>{wifiScan.currentNetwork.routerVendor}</Text>
                  </View>
                )}
                {wifiScan.currentNetwork.estimatedSpeed && (
                  <View style={styles.networkRow}>
                    <Text style={styles.networkLabel}>Est. Speed:</Text>
                    <Text style={styles.networkValue}>{wifiScan.currentNetwork.estimatedSpeed} Mbps</Text>
                  </View>
                )}
                {wifiScan.currentNetwork.channelWidth && (
                  <View style={styles.networkRow}>
                    <Text style={styles.networkLabel}>Channel:</Text>
                    <Text style={styles.networkValue}>
                      {wifiScan.currentNetwork.channel} ({wifiScan.currentNetwork.channelWidth}MHz)
                    </Text>
                  </View>
                )}
                {wifiScan.currentNetwork.interferenceLevel && (
                  <View style={styles.networkRow}>
                    <Text style={styles.networkLabel}>Interference:</Text>
                    <Text style={[styles.networkValue, {
                      color: wifiScan.currentNetwork.interferenceLevel === 'high' ? '#f44336' :
                             wifiScan.currentNetwork.interferenceLevel === 'medium' ? '#ff9800' : '#4caf50'
                    }]}>
                      {wifiScan.currentNetwork.interferenceLevel.toUpperCase()}
                    </Text>
                  </View>
                )}
                {wifiScan.currentNetwork.connectedDevices && (
                  <View style={styles.networkRow}>
                    <Text style={styles.networkLabel}>Connected Devices:</Text>
                    <Text style={styles.networkValue}>{wifiScan.currentNetwork.connectedDevices}</Text>
                  </View>
                )}
              </View>

              {wifiScan.currentNetwork.vulnerabilities.length > 0 && (
                <View style={styles.threatsContainer}>
                  <Text style={styles.threatsTitle}>⚠️ Vulnerabilities Detected:</Text>
                  {wifiScan.currentNetwork.vulnerabilities.map((vuln, index) => (
                    <Text key={index} style={styles.threatItem}>• {vuln}</Text>
                  ))}
                </View>
              )}

              {wifiScan.currentNetwork.recommendations.length > 0 && (
                <View style={styles.recommendationsContainer}>
                  <Text style={styles.recommendationsTitle}>💡 Recommendations:</Text>
                  {wifiScan.currentNetwork.recommendations.map((rec, index) => (
                    <Text key={index} style={styles.recommendationItem}>• {rec}</Text>
                  ))}
                </View>
              )}
            </Card.Content>
          </Card>
        )}

        {/* Channel Analysis */}
        {wifiScan?.channelAnalysis && (
          <Card style={styles.card}>
            <Card.Title 
              title="Channel Analysis" 
              left={props => <Icon name="chart-line" {...props} />} 
            />
            <Card.Content>
              <View style={styles.channelInfo}>
                <View style={styles.channelStat}>
                  <Text style={styles.channelLabel}>Current Channel</Text>
                  <Text style={styles.channelValue}>{wifiScan.channelAnalysis.channel}</Text>
                </View>
                <View style={styles.channelStat}>
                  <Text style={styles.channelLabel}>Networks on Channel</Text>
                  <Text style={styles.channelValue}>{wifiScan.channelAnalysis.networksOnChannel}</Text>
                </View>
                <View style={styles.channelStat}>
                  <Text style={styles.channelLabel}>Interference</Text>
                  <Text style={[styles.channelValue, {
                    color: wifiScan.channelAnalysis.interferenceLevel === 'high' ? '#f44336' :
                           wifiScan.channelAnalysis.interferenceLevel === 'medium' ? '#ff9800' : '#4caf50'
                  }]}>
                    {wifiScan.channelAnalysis.interferenceLevel.toUpperCase()}
                  </Text>
                </View>
              </View>
              {wifiScan.channelAnalysis.recommendedChannels.length > 0 && (
                <View style={styles.recommendedChannels}>
                  <Text style={styles.recommendedTitle}>📡 Best Channels:</Text>
                  <Text style={styles.recommendedText}>
                    {wifiScan.channelAnalysis.recommendedChannels.join(', ')}
                  </Text>
                </View>
              )}
            </Card.Content>
          </Card>
        )}

        {/* Threats Overview */}
        {wifiScan && wifiScan.threats.length > 0 && (
          <Card style={styles.card}>
            <Card.Title 
              title={`Security Threats (${wifiScan.threats.length})`}
              left={props => <Icon name="shield-alert" {...props} />} 
            />
            <Card.Content>
              {wifiScan.threats.map((threat, index) => (
                <View key={threat.id} style={styles.wifiThreatCard}>
                  <View style={styles.wifiThreatHeader}>
                    <Icon 
                      name={threat.severity === 'critical' ? 'alert-octagon' : 'alert'} 
                      size={20} 
                      color={WiFiSecurityService.getThreatColor(threat.severity)} 
                    />
                    <Chip 
                      compact
                      style={[styles.severityChip, {backgroundColor: WiFiSecurityService.getThreatColor(threat.severity)}]}
                      textStyle={{color: '#fff', fontSize: 10}}>
                      {threat.severity.toUpperCase()}
                    </Chip>
                    {threat.confidence && (
                      <Text style={styles.confidenceText}>{threat.confidence}% confident</Text>
                    )}
                  </View>
                  <Text style={styles.wifiThreatNetwork}>Network: {threat.network}</Text>
                  <Text style={styles.wifiThreatDescription}>{threat.description}</Text>
                  <Text style={styles.wifiThreatRecommendation}>💡 {threat.recommendation}</Text>
                  {index < wifiScan.threats.length - 1 && <Divider style={styles.wifiThreatDivider} />}
                </View>
              ))}
            </Card.Content>
          </Card>
        )}

        {/* Evil Twin Warning */}
        {wifiScan?.evilTwinDetected && (
          <Card style={[styles.card, {backgroundColor: '#fff3e0'}]}>
            <Card.Content>
              <View style={styles.warningHeader}>
                <Icon name="alert-octagon" size={24} color="#f44336" />
                <Text style={styles.warningTitle}>Evil Twin Attack Detected!</Text>
              </View>
              <Text style={styles.warningText}>
                Multiple networks with identical names detected. This could be a malicious access point.
              </Text>
              <Text style={styles.warningDuplicates}>
                Duplicate SSIDs: {wifiScan.duplicateSSIDs?.join(', ')}
              </Text>
            </Card.Content>
          </Card>
        )}

        {/* Scan Button */}
        <Button 
          mode="contained" 
          onPress={() => {
            console.log('🔘 WiFi Scan Button Pressed!');
            handleWiFiScan();
          }}
          loading={isScanning}
          disabled={isScanning}
          icon="wifi-strength-4"
          style={styles.scanButton}>
          {isScanning ? 'Scanning Networks...' : 'Scan WiFi Networks'}
        </Button>

        {/* Network Statistics */}
        {wifiScan && (
          <Card style={styles.card}>
            <Card.Title 
              title="Network Statistics" 
              left={props => <Icon name="chart-bar" {...props} />} 
            />
            <Card.Content>
              <View style={styles.statsGrid}>
                <View style={styles.statBox}>
                  <Text style={styles.statValue}>{wifiScan.totalNetworks}</Text>
                  <Text style={styles.statLabel}>Total Networks</Text>
                </View>
                <View style={styles.statBox}>
                  <Text style={[styles.statValue, {color: '#4caf50'}]}>{wifiScan.secureNetworks}</Text>
                  <Text style={styles.statLabel}>Secure</Text>
                </View>
                <View style={styles.statBox}>
                  <Text style={[styles.statValue, {color: '#f44336'}]}>{wifiScan.insecureNetworks}</Text>
                  <Text style={styles.statLabel}>Insecure</Text>
                </View>
                <View style={styles.statBox}>
                  <Text style={[styles.statValue, {color: '#ff9800'}]}>{wifiScan.threats.length}</Text>
                  <Text style={styles.statLabel}>Threats</Text>
                </View>
              </View>
            </Card.Content>
          </Card>
        )}

        {/* Nearby Networks */}
        {wifiScan && wifiScan.nearbyNetworks.length > 0 && (
          <Card style={styles.card}>
            <Card.Title 
              title={`Nearby Networks (${wifiScan.nearbyNetworks.length})`}
              subtitle="First network is your actual connection, others are simulated examples"
              left={props => <Icon name="wifi-marker" {...props} />} 
            />
            <Card.Content>
              <Text style={[styles.networkItemText, {marginBottom: 12, fontStyle: 'italic', color: '#666'}]}>
                ℹ️ Note: Due to platform restrictions, only your current network is real. Nearby networks are simulated based on common patterns.
              </Text>
              {wifiScan.nearbyNetworks.map((network, index) => (
                <View key={index} style={styles.networkItem}>
                  <View style={styles.networkItemHeader}>
                    <Icon name="wifi" size={20} color={theme.colors.primary} />
                    <Text style={styles.networkItemName}>{network.ssid}</Text>
                    <Chip 
                      compact
                      style={[styles.ratingChipSmall, {backgroundColor: getSecurityRatingColor(network.securityRating)}]}
                      textStyle={{color: '#fff', fontSize: 10}}>
                      {network.securityRating.toUpperCase()}
                    </Chip>
                  </View>
                  <View style={styles.networkItemDetails}>
                    <Text style={styles.networkItemText}>
                      {network.encryptionType} • Signal: {network.signalStrength}/100
                    </Text>
                    {network.routerVendor && (
                      <Text style={styles.networkItemText}>
                        {network.routerVendor} • {network.estimatedSpeed} Mbps
                      </Text>
                    )}
                    {network.interferenceLevel && network.interferenceLevel !== 'none' && (
                      <Text style={[styles.networkItemText, {color: '#ff9800'}]}>
                        ⚠️ {network.interferenceLevel.toUpperCase()} interference on channel {network.channel}
                      </Text>
                    )}
                  </View>
                  {network.vulnerabilities.length > 0 && (
                    <View style={styles.networkThreats}>
                      <Icon name="alert" size={14} color="#f44336" />
                      <Text style={styles.networkThreatText}>{network.vulnerabilities.length} vulnerability(s) detected</Text>
                    </View>
                  )}
                  {index < wifiScan.nearbyNetworks.length - 1 && <Divider style={styles.networkDivider} />}
                </View>
              ))}
            </Card.Content>
          </Card>
        )}
      </>
    );
  }

  function renderPrivacyTab() {
    return (
      <>
        {/* Privacy Score */}
        <Card style={styles.card}>
          <Card.Title 
            title="Privacy Score" 
            left={props => <Icon name="eye-off" {...props} />} 
          />
          <Card.Content>
            <View style={styles.privacyScoreContainer}>
              <View style={styles.privacyScoreCircle}>
                <Text style={[styles.privacyScoreText, {color: getPrivacyScoreColor(privacyScore?.overall || 0)}]}>
                  {privacyScore?.overall || 0}
                </Text>
                <Text style={styles.privacyScoreLabel}>Privacy Score</Text>
              </View>
              
              <View style={styles.privacyBreakdown}>
                <View style={styles.privacyItem}>
                  <Text style={styles.privacyItemLabel}>Permissions</Text>
                  <Text style={styles.privacyItemValue}>{privacyScore?.breakdown.permissions || 0}/100</Text>
                </View>
                <View style={styles.privacyItem}>
                  <Text style={styles.privacyItemLabel}>Tracking</Text>
                  <Text style={styles.privacyItemValue}>{privacyScore?.breakdown.tracking || 0}/100</Text>
                </View>
                <View style={styles.privacyItem}>
                  <Text style={styles.privacyItemLabel}>Data Sharing</Text>
                  <Text style={styles.privacyItemValue}>{privacyScore?.breakdown.dataSharing || 0}/100</Text>
                </View>
                <View style={styles.privacyItem}>
                  <Text style={styles.privacyItemLabel}>Encryption</Text>
                  <Text style={styles.privacyItemValue}>{privacyScore?.breakdown.encryption || 0}/100</Text>
                </View>
              </View>
            </View>

            <Text style={styles.privacyRisk}>
              Rating: <Text style={{color: getPrivacyScoreColor(privacyScore?.overall || 0)}}>
                {privacyScore?.rating?.toUpperCase() || 'UNKNOWN'}
              </Text>
            </Text>

            {privacyScore && privacyScore.improvements && privacyScore.improvements.length > 0 && (
              <View style={styles.privacyIssues}>
                <Text style={styles.privacyIssuesTitle}>💡 Improvements:</Text>
                {privacyScore.improvements.map((improvement, index) => (
                  <Text key={index} style={styles.privacyIssueItem}>• {improvement}</Text>
                ))}
              </View>
            )}
          </Card.Content>
        </Card>

        {/* Today's Activity */}
        <Card style={styles.card}>
          <Card.Title 
            title="Today's Permission Activity" 
            left={props => <Icon name="history" {...props} />} 
          />
          <Card.Content>
            {permissionActivity && permissionActivity.length > 0 ? (
              permissionActivity.map((activity, index) => (
                <View key={index} style={styles.activityItem}>
                  <View style={styles.activityHeader}>
                    <Icon name={getPermissionIcon(activity.permission)} size={20} color={theme.colors.primary} />
                    <Text style={styles.activityApp}>{activity.app}</Text>
                    <Text style={styles.activityTime}>{new Date(activity.timestamp).toLocaleTimeString()}</Text>
                  </View>
                  <Text style={styles.activityPermission}>
                    Accessed: {activity.permissionName}
                  </Text>
                  {activity.isSuspicious && (
                    <View style={styles.suspiciousFlag}>
                      <Icon name="alert-circle" size={14} color="#ff9800" />
                      <Text style={styles.suspiciousText}>Suspicious activity detected</Text>
                    </View>
                  )}
                  {index < permissionActivity.length - 1 && <Divider style={styles.activityDivider} />}
                </View>
              ))
            ) : (
              <Text style={styles.emptyText}>No permission activity today</Text>
            )}
          </Card.Content>
        </Card>
      </>
    );
  }

  function renderTrafficTab() {
    return (
      <>
        {/* Active Connections */}
        <Card style={styles.card}>
          <Card.Title 
            title={`Active Connections (${networkConnections.length})`}
            left={props => <Icon name="wan" {...props} />} 
          />
          <Card.Content>
            {networkConnections.length > 0 ? (
              networkConnections.map((conn, index) => (
                <View key={index} style={styles.connectionItem}>
                  <View style={styles.connectionHeader}>
                    <Icon name={getProtocolIcon(conn.protocol)} size={20} color={theme.colors.primary} />
                    <Text style={styles.connectionApp}>{conn.app}</Text>
                    <Chip 
                      compact
                      style={[styles.threatLevelChip, {backgroundColor: getThreatLevelColor(conn.threatLevel)}]}
                      textStyle={{color: '#fff', fontSize: 10}}>
                      {conn.threatLevel.toUpperCase()}
                    </Chip>
                  </View>
                  
                  <View style={styles.connectionDetails}>
                    <Text style={styles.connectionText}>
                      {conn.remoteAddress}:{conn.remotePort}
                    </Text>
                    <Text style={styles.connectionText}>
                      {conn.protocol} • {conn.country}
                    </Text>
                  </View>

                  {conn.isSuspicious && (
                    <View style={styles.suspiciousConnection}>
                      <Icon name="shield-alert" size={14} color="#f44336" />
                      <Text style={styles.suspiciousConnectionText}>Suspicious connection detected</Text>
                    </View>
                  )}

                  {index < networkConnections.length - 1 && <Divider style={styles.connectionDivider} />}
                </View>
              ))
            ) : (
              <Text style={styles.emptyText}>No active connections</Text>
            )}
          </Card.Content>
        </Card>

        {/* Traffic Statistics */}
        {trafficStats && (
          <Card style={styles.card}>
            <Card.Title 
              title="Traffic Statistics" 
              left={props => <Icon name="chart-line" {...props} />} 
            />
            <Card.Content>
              <View style={styles.statsRow}>
                <View style={styles.statItem}>
                  <Icon name="download" size={24} color="#4caf50" />
                  <Text style={styles.statLabel}>Downloaded</Text>
                  <Text style={styles.statValue}>{(trafficStats.totalBytesIn / 1024 / 1024).toFixed(2)} MB</Text>
                </View>
                <View style={styles.statItem}>
                  <Icon name="upload" size={24} color="#2196f3" />
                  <Text style={styles.statLabel}>Uploaded</Text>
                  <Text style={styles.statValue}>{(trafficStats.totalBytesOut / 1024 / 1024).toFixed(2)} MB</Text>
                </View>
              </View>

              <Divider style={styles.statsDivider} />

              <View style={styles.trafficInfo}>
                <Text style={styles.trafficInfoTitle}>Top Applications:</Text>
                {trafficStats.topApps.map((app: any, index: number) => (
                  <View key={index} style={styles.topAppItem}>
                    <Text style={styles.topAppName}>{app.app}</Text>
                    <Text style={styles.topAppData}>{((app.bytesIn + app.bytesOut) / 1024 / 1024).toFixed(2)} MB</Text>
                  </View>
                ))}
              </View>

              <Divider style={styles.statsDivider} />

              <View style={styles.trafficInfo}>
                <Text style={styles.trafficInfoTitle}>Top Countries:</Text>
                {trafficStats.topCountries.map((country, index) => (
                  <View key={index} style={styles.topCountryItem}>
                    <Text style={styles.topCountryName}>{country.country}</Text>
                    <Text style={styles.topCountryCount}>{country.connections} connections</Text>
                  </View>
                ))}
              </View>

              <Divider style={styles.statsDivider} />

              <View style={styles.trafficInfo}>
                <Text style={styles.trafficInfoTitle}>Protocol Distribution:</Text>
                {Object.entries(trafficStats.protocolDistribution).map(([protocol, count]) => (
                  <View key={protocol} style={styles.protocolItem}>
                    <Text style={styles.protocolName}>{protocol}</Text>
                    <Text style={styles.protocolCount}>{count}</Text>
                  </View>
                ))}
              </View>
            </Card.Content>
          </Card>
        )}

        {/* Suspicious Activities */}
        {suspiciousActivities && suspiciousActivities.length > 0 && (
          <Card style={styles.card}>
            <Card.Title 
              title="Suspicious Activities" 
              left={props => <Icon name="alert-octagon" {...props} />} 
            />
            <Card.Content>
              {suspiciousActivities.map((activity: any, index: number) => (
                <View key={index} style={styles.suspiciousActivityItem}>
                  <View style={styles.suspiciousActivityHeader}>
                    <Icon name="alert" size={20} color="#f44336" />
                    <Text style={styles.suspiciousActivityType}>{activity.type}</Text>
                    <Chip 
                      compact
                      style={[styles.severityChip, {backgroundColor: getSeverityColor(activity.severity)}]}
                      textStyle={{color: '#fff', fontSize: 10}}>
                      {activity.severity.toUpperCase()}
                    </Chip>
                  </View>
                  <Text style={styles.suspiciousActivityDesc}>{activity.description}</Text>
                  <Text style={styles.suspiciousActivityTime}>
                    {new Date(activity.timestamp).toLocaleString()}
                  </Text>
                  {index < suspiciousActivities.length - 1 && <Divider style={styles.activityDivider} />}
                </View>
              ))}
            </Card.Content>
          </Card>
        )}
      </>
    );
  }
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  header: {
    padding: 20,
    alignItems: 'center',
    elevation: 2,
    marginBottom: 16,
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    marginTop: 12,
  },
  headerSubtitle: {
    fontSize: 14,
    color: '#666',
    marginTop: 4,
  },
  dataSourceBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 8,
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 12,
    alignSelf: 'flex-start',
  },
  dataSourceText: {
    fontSize: 12,
    fontWeight: '600',
    marginLeft: 6,
  },
  card: {
    margin: 12,
    marginTop: 0,
    marginBottom: 16,
  },
  scoreContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  scoreCircle: {
    alignItems: 'center',
  },
  scoreText: {
    fontSize: 48,
    fontWeight: 'bold',
  },
  scoreLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  scoreDetails: {
    flex: 1,
    marginLeft: 20,
    gap: 8,
  },
  warningChip: {
    backgroundColor: '#ffebee',
    marginBottom: 4,
  },
  successChip: {
    backgroundColor: '#e8f5e9',
    marginBottom: 4,
  },
  infoChip: {
    backgroundColor: '#e3f2fd',
    marginBottom: 4,
  },
  recommendationItem: {
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  recommendationText: {
    fontSize: 14,
    lineHeight: 20,
  },
  metricRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 8,
  },
  metricLabel: {
    flex: 1,
    marginLeft: 12,
    fontSize: 16,
  },
  metricValue: {
    fontSize: 14,
    color: '#666',
  },
  progressBar: {
    height: 8,
    borderRadius: 4,
    marginTop: 8,
  },
  storageText: {
    textAlign: 'center',
    marginTop: 4,
    fontSize: 12,
    color: '#666',
  },
  urlInput: {
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 8,
    padding: 12,
    marginBottom: 12,
    fontSize: 14,
  },
  checkButton: {
    marginBottom: 16,
  },
  urlResultContainer: {
    marginTop: 8,
  },
  urlResultHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 16,
    borderRadius: 8,
    marginBottom: 12,
  },
  urlResultTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginLeft: 12,
  },
  threatDetails: {
    backgroundColor: '#f5f5f5',
    padding: 16,
    borderRadius: 8,
  },
  threatRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  threatLabel: {
    fontSize: 14,
    fontWeight: '600',
  },
  threatChip: {
    color: '#fff',
  },
  threatDescription: {
    fontSize: 14,
    marginTop: 8,
    lineHeight: 20,
  },
  threatReason: {
    fontSize: 12,
    color: '#666',
    marginTop: 8,
    fontStyle: 'italic',
  },
  // Tab styles
  tabContainer: {
    paddingHorizontal: 12,
    marginBottom: 16,
  },
  segmentedButtons: {
    backgroundColor: '#fff',
  },
  // WiFi tab styles
  networkHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  networkName: {
    fontSize: 18,
    fontWeight: 'bold',
  },
  ratingChip: {
    paddingHorizontal: 8,
  },
  networkDetails: {
    backgroundColor: '#f5f5f5',
    padding: 12,
    borderRadius: 8,
    marginBottom: 12,
  },
  networkRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 4,
  },
  networkLabel: {
    fontSize: 14,
    color: '#666',
  },
  networkValue: {
    fontSize: 14,
    fontWeight: '600',
  },
  threatsContainer: {
    backgroundColor: '#ffebee',
    padding: 12,
    borderRadius: 8,
    marginTop: 12,
  },
  threatsTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 8,
    color: '#d32f2f',
  },
  threatItem: {
    fontSize: 13,
    color: '#d32f2f',
    marginBottom: 4,
  },
  recommendationsContainer: {
    backgroundColor: '#e3f2fd',
    padding: 12,
    borderRadius: 8,
    marginTop: 12,
  },
  recommendationsTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 8,
    color: '#1976d2',
  },
  scanButton: {
    margin: 12,
    marginTop: 0,
  },
  networkItem: {
    paddingVertical: 12,
  },
  networkItemHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  networkItemName: {
    flex: 1,
    fontSize: 16,
    fontWeight: '600',
    marginLeft: 8,
  },
  ratingChipSmall: {
    height: 20,
  },
  networkItemDetails: {
    marginLeft: 28,
    marginBottom: 4,
  },
  networkItemText: {
    fontSize: 12,
    color: '#666',
  },
  networkThreats: {
    flexDirection: 'row',
    alignItems: 'center',
    marginLeft: 28,
    marginTop: 4,
  },
  networkThreatText: {
    fontSize: 12,
    color: '#f44336',
    marginLeft: 4,
  },
  networkDivider: {
    marginTop: 12,
  },
  // Privacy tab styles
  privacyScoreContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16,
  },
  privacyScoreCircle: {
    alignItems: 'center',
    marginRight: 20,
  },
  privacyScoreText: {
    fontSize: 48,
    fontWeight: 'bold',
  },
  privacyScoreLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  privacyBreakdown: {
    flex: 1,
  },
  privacyItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 4,
  },
  privacyItemLabel: {
    fontSize: 14,
    color: '#666',
  },
  privacyItemValue: {
    fontSize: 14,
    fontWeight: '600',
  },
  privacyRisk: {
    fontSize: 16,
    textAlign: 'center',
    marginTop: 12,
    fontWeight: '600',
  },
  privacyIssues: {
    backgroundColor: '#fff3e0',
    padding: 12,
    borderRadius: 8,
    marginTop: 16,
  },
  privacyIssuesTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 8,
    color: '#f57c00',
  },
  privacyIssueItem: {
    fontSize: 13,
    color: '#e65100',
    marginBottom: 4,
  },
  activityItem: {
    paddingVertical: 12,
  },
  activityHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 4,
  },
  activityApp: {
    flex: 1,
    fontSize: 16,
    fontWeight: '600',
    marginLeft: 8,
  },
  activityTime: {
    fontSize: 12,
    color: '#666',
  },
  activityPermission: {
    fontSize: 13,
    color: '#666',
    marginLeft: 28,
    marginTop: 2,
  },
  suspiciousFlag: {
    flexDirection: 'row',
    alignItems: 'center',
    marginLeft: 28,
    marginTop: 4,
  },
  suspiciousText: {
    fontSize: 12,
    color: '#ff9800',
    marginLeft: 4,
  },
  activityDivider: {
    marginTop: 12,
  },
  emptyText: {
    fontSize: 14,
    color: '#999',
    textAlign: 'center',
    paddingVertical: 20,
  },
  // Traffic tab styles
  connectionItem: {
    paddingVertical: 12,
  },
  connectionHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  connectionApp: {
    flex: 1,
    fontSize: 16,
    fontWeight: '600',
    marginLeft: 8,
  },
  threatLevelChip: {
    height: 20,
  },
  connectionDetails: {
    marginLeft: 28,
  },
  connectionText: {
    fontSize: 12,
    color: '#666',
    marginBottom: 2,
  },
  suspiciousConnection: {
    flexDirection: 'row',
    alignItems: 'center',
    marginLeft: 28,
    marginTop: 4,
  },
  suspiciousConnectionText: {
    fontSize: 12,
    color: '#f44336',
    marginLeft: 4,
  },
  connectionDivider: {
    marginTop: 12,
  },
  statsRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginBottom: 16,
  },
  statItem: {
    alignItems: 'center',
  },
  statLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  statValue: {
    fontSize: 16,
    fontWeight: 'bold',
    marginTop: 2,
  },
  statsDivider: {
    marginVertical: 16,
  },
  trafficInfo: {
    marginBottom: 8,
  },
  trafficInfoTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 8,
  },
  topAppItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 4,
  },
  topAppName: {
    fontSize: 13,
    color: '#666',
  },
  topAppData: {
    fontSize: 13,
    fontWeight: '600',
  },
  topCountryItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 4,
  },
  topCountryName: {
    fontSize: 13,
    color: '#666',
  },
  topCountryCount: {
    fontSize: 13,
    fontWeight: '600',
  },
  protocolItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 4,
  },
  protocolName: {
    fontSize: 13,
    color: '#666',
  },
  protocolCount: {
    fontSize: 13,
    fontWeight: '600',
  },
  suspiciousActivityItem: {
    paddingVertical: 12,
  },
  suspiciousActivityHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  suspiciousActivityType: {
    flex: 1,
    fontSize: 16,
    fontWeight: '600',
    marginLeft: 8,
  },
  severityChip: {
    height: 20,
  },
  suspiciousActivityDesc: {
    fontSize: 13,
    color: '#666',
    marginLeft: 28,
    marginBottom: 4,
  },
  suspiciousActivityTime: {
    fontSize: 11,
    color: '#999',
    marginLeft: 28,
  },
  // Enhanced WiFi styles
  channelInfo: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginBottom: 16,
  },
  channelStat: {
    alignItems: 'center',
  },
  channelLabel: {
    fontSize: 12,
    color: '#666',
    marginBottom: 4,
  },
  channelValue: {
    fontSize: 18,
    fontWeight: 'bold',
  },
  recommendedChannels: {
    backgroundColor: '#e8f5e9',
    padding: 12,
    borderRadius: 8,
  },
  recommendedTitle: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 4,
  },
  recommendedText: {
    fontSize: 14,
    color: '#4caf50',
  },
  wifiThreatCard: {
    marginBottom: 16,
  },
  wifiThreatHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
    gap: 8,
  },
  confidenceText: {
    fontSize: 11,
    color: '#666',
    marginLeft: 'auto',
  },
  wifiThreatNetwork: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 4,
  },
  wifiThreatDescription: {
    fontSize: 13,
    color: '#666',
    marginBottom: 8,
  },
  wifiThreatRecommendation: {
    fontSize: 13,
    color: '#1976d2',
    fontStyle: 'italic',
  },
  wifiThreatDivider: {
    marginTop: 12,
  },
  warningHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 12,
    gap: 12,
  },
  warningTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#f44336',
  },
  warningText: {
    fontSize: 14,
    color: '#666',
    marginBottom: 8,
  },
  warningDuplicates: {
    fontSize: 13,
    fontWeight: '600',
    color: '#f44336',
  },
  statsGrid: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    flexWrap: 'wrap',
  },
  statBox: {
    alignItems: 'center',
    minWidth: '22%',
    marginBottom: 8,
  },
});

// Helper functions for colors
function getSecurityScoreColor(score: number): string {
  if (score >= 80) return '#4caf50';
  if (score >= 60) return '#ff9800';
  return '#f44336';
}

function getThreatLevelColor(level: string): string {
  switch (level) {
    case 'critical': return '#b71c1c';
    case 'high': return '#f44336';
    case 'medium': return '#ff9800';
    case 'low': return '#ffc107';
    case 'safe': return '#4caf50';
    default: return '#757575';
  }
}

function getSecurityRatingColor(rating: string): string {
  switch (rating) {
    case 'excellent': return '#4caf50';
    case 'good': return '#8bc34a';
    case 'fair': return '#ffc107';
    case 'poor': return '#ff9800';
    case 'critical': return '#f44336';
    default: return '#757575';
  }
}

function getPrivacyScoreColor(score: number): string {
  if (score >= 80) return '#4caf50';
  if (score >= 60) return '#ff9800';
  return '#f44336';
}

function getRiskLevelColor(level: string): string {
  switch (level) {
    case 'low': return '#4caf50';
    case 'medium': return '#ff9800';
    case 'high': return '#f44336';
    case 'critical': return '#b71c1c';
    default: return '#757575';
  }
}

function getPermissionIcon(permission: string): any {
  switch (permission.toLowerCase()) {
    case 'camera': return 'camera';
    case 'microphone': return 'microphone';
    case 'location': return 'map-marker';
    case 'contacts': return 'contacts';
    case 'photos': return 'image';
    case 'calendar': return 'calendar';
    case 'bluetooth': return 'bluetooth';
    case 'notifications': return 'bell';
    default: return 'shield';
  }
}

function getProtocolIcon(protocol: string): any {
  switch (protocol.toUpperCase()) {
    case 'HTTP':
    case 'HTTPS': return 'web';
    case 'TCP': return 'lan';
    case 'UDP': return 'access-point';
    default: return 'network';
  }
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return '#b71c1c';
    case 'high': return '#f44336';
    case 'medium': return '#ff9800';
    case 'low': return '#ffc107';
    default: return '#757575';
  }
}

export default MobileProtectionScreen;
