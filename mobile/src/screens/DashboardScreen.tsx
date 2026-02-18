import React, {useEffect, useState, useRef} from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  TouchableOpacity,
  Dimensions,
  Alert,
} from 'react-native';
import {Card, Button, ProgressBar, Chip, Surface, useTheme} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import {LineChart} from 'react-native-chart-kit';
import {SocketService} from '../services/SocketService';
import ApiService from '../services/ApiService';

const DashboardScreen = (): JSX.Element => {
  const theme = useTheme();
  const [refreshing, setRefreshing] = useState(false);
  const [useWebSocket, setUseWebSocket] = useState(false);
  const [isOffline, setIsOffline] = useState(false);
  const scanPollIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const [metrics, setMetrics] = useState({
    cpu: 0,
    memory: 0,
    disk: 0,
    threats: 0,
    lastScan: null,
  });
  const [scanStatus, setScanStatus] = useState({
    isScanning: false,
    progress: 0,
    filesScanned: 0,
  });
  const [cpuHistory, setCpuHistory] = useState([0, 0, 0, 0, 0, 0]);
  const [isLoadingStatus, setIsLoadingStatus] = useState(false);

  const loadSystemStatus = async () => {
    // Prevent overlapping requests
    if (isLoadingStatus) {
      console.log('Skipping system status request - previous request still pending');
      return;
    }

    setIsLoadingStatus(true);
    try {
      const result = await ApiService.getSystemStatus();
      if (result.success && result.data) {
        updateMetrics(result.data);
        setIsOffline(result.offline || false);
      }
    } finally {
      setIsLoadingStatus(false);
    }
  };

  const updateMetrics = (data: any) => {
    setMetrics({
      cpu: data.cpu?.usage || 0,
      memory: data.memory?.usagePercent || 0,
      disk: data.disk?.usagePercent || 0,
      threats: data.threats || 0,
      lastScan: data.lastScan || null,
    });
    setCpuHistory(prev => [...prev.slice(-5), data.cpu?.usage || 0]);
  };

  useEffect(() => {
    // Check if WebSocket is connected
    const isSocketConnected = SocketService.isConnected();
    setUseWebSocket(isSocketConnected);

    if (isSocketConnected) {
      console.log('✅ Using WebSocket for real-time updates');
      
      // Listen for real-time metrics
      SocketService.on('metrics:data', (data) => {
        console.log('📊 Received real-time metrics:', data);
        updateMetrics(data);
      });

      // Listen for scan updates
      SocketService.on('scan:update', (data) => {
        console.log('🔍 Scan update:', data);
        setScanStatus({
          isScanning: data.scanning || false,
          progress: data.progress || 0,
          filesScanned: data.filesScanned || 0,
        });

        if (!data.scanning && scanPollIntervalRef.current) {
          clearInterval(scanPollIntervalRef.current);
          scanPollIntervalRef.current = null;
          Alert.alert('Scan Complete', `Scanned ${data.filesScanned || 0} files`);
        }
      });

      // Listen for threat alerts
      SocketService.on('threat:alert', (data) => {
        console.log('⚠️ Threat detected:', data);
        Alert.alert(
          '⚠️ Threat Detected',
          `${data.threatName}\nSeverity: ${data.severity}\nAction: ${data.action}`,
          [{text: 'OK'}]
        );
        loadSystemStatus(); // Refresh metrics
      });

      // Request initial metrics
      loadSystemStatus();
    } else {
      console.log('📡 WebSocket not connected, using HTTP polling');
      
      // Load initial data from API
      loadSystemStatus();
      
      // Poll for updates every 10 seconds
      pollingIntervalRef.current = setInterval(() => {
        loadSystemStatus();
      }, 10000);
    }

    return () => {
      // Cleanup
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
      if (scanPollIntervalRef.current) {
        clearInterval(scanPollIntervalRef.current);
      }
      
      // Remove WebSocket listeners
      SocketService.off('metrics:data');
      SocketService.off('scan:update');
      SocketService.off('threat:alert');
    };
  }, []);

  const onRefresh = async () => {
    setRefreshing(true);
    await loadSystemStatus();
    setRefreshing(false);
  };

  const handleStartScan = async () => {
    // Clear any existing scan poll interval
    if (scanPollIntervalRef.current) {
      clearInterval(scanPollIntervalRef.current);
      scanPollIntervalRef.current = null;
    }

    const result = await ApiService.startScan('quick');
    if (result.success) {
      setScanStatus({
        isScanning: true,
        progress: 0,
        filesScanned: 0,
      });
      Alert.alert('Scan Started', 'Quick scan is now running...');
      
      // Poll for scan status updates
      scanPollIntervalRef.current = setInterval(async () => {
        const statusResult = await ApiService.getScanStatus();
        if (statusResult.success && statusResult.data) {
          const isScanning = statusResult.data.scanning || false;
          
          if (!isScanning) {
            // Clear interval when scan completes
            if (scanPollIntervalRef.current) {
              clearInterval(scanPollIntervalRef.current);
              scanPollIntervalRef.current = null;
            }
            setScanStatus({
              isScanning: false,
              progress: 100,
              filesScanned: statusResult.data.filesScanned || 0,
            });
            Alert.alert('Scan Complete', `Scanned ${statusResult.data.filesScanned || 0} files`);
            await loadSystemStatus(); // Refresh metrics
          } else {
            setScanStatus({
              isScanning: true,
              progress: statusResult.data.progress || 0,
              filesScanned: statusResult.data.filesScanned || 0,
            });
          }
        }
      }, 2000); // Poll every 2 seconds
    } else {
      Alert.alert('Scan Failed', result.error || 'Failed to start scan');
    }
  };

  const getStatusColor = (value: number) => {
    if (value < 50) return '#4caf50';
    if (value < 80) return '#ff9800';
    return '#f44336';
  };

  const handleUpdate = async () => {
    const result = await ApiService.updateSignatures();
    if (result.success) {
      const data = result.data;
      const message = data.newSignatures 
        ? `Updated successfully!\n\n• New signatures: ${data.newSignatures}\n• Total signatures: ${data.totalSignatures.toLocaleString()}\n• Source: ${data.source || 'VirusTotal'}`
        : `Updated successfully!\n\n• Total signatures: ${data.totalSignatures.toLocaleString()}\n• Source: ${data.source || 'VirusTotal'}\n• Engines: ${data.engines || 'N/A'}`;
      
      Alert.alert('✅ Signatures Updated', message, [{text: 'OK'}]);
      await loadSystemStatus();
    } else {
      Alert.alert('Update Failed', result.error || 'Failed to update signatures');
    }
  };

  const handleRefresh = async () => {
    await loadSystemStatus();
    Alert.alert('Refreshed', 'System status updated');
  };

  return (
    <ScrollView
      style={[styles.container, {backgroundColor: theme.colors.background}]}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
      }>
      
      {/* Offline Banner */}
      {isOffline && (
        <Card style={[styles.card, { backgroundColor: '#fff3cd', borderLeftWidth: 4, borderLeftColor: '#ff9800' }]}>
          <Card.Content>
            <View style={{ flexDirection: 'row', alignItems: 'center' }}>
              <Icon name="wifi-off" size={24} color="#ff9800" style={{ marginRight: 12 }} />
              <View style={{ flex: 1 }}>
                <Text style={{ fontWeight: 'bold', color: '#856404', marginBottom: 4 }}>
                  Backend Server Not Connected
                </Text>
                <Text style={{ color: '#856404', fontSize: 12 }}>
                  Showing demo data. To connect:{'\n'}
                  1. Ensure mobile-api-server.js is running on your PC{'\n'}
                  2. Update IP in ApiService.ts to your PC's WiFi IP{'\n'}
                  3. Ensure phone and PC are on same network
                </Text>
              </View>
            </View>
          </Card.Content>
        </Card>
      )}
      
      {/* Status Header with Connection Indicator */}
      <Surface style={styles.headerCard} elevation={2}>
        <View style={styles.headerContent}>
          <View style={styles.headerWithConnection}>
            <View style={styles.statusRow}>
              <Icon name="shield-check" size={40} color="#4caf50" />
              <View style={styles.statusText}>
                <Text style={styles.statusTitle}>Protected</Text>
                <Text style={styles.statusSubtitle}>All systems operational</Text>
              </View>
            </View>
            <View style={styles.connectionIndicator}>
              <View style={[styles.connectionDot, { backgroundColor: isOffline ? '#f44336' : (useWebSocket ? '#4caf50' : '#ff9800') }]} />
              <Text style={styles.connectionText}>
                {isOffline ? 'Offline - Demo Mode' : (useWebSocket ? 'Live Updates' : 'Polling Mode')}
              </Text>
            </View>
          </View>
          <Chip icon="alert-circle" mode="flat" style={styles.threatChip}>
            {metrics.threats} Threats Blocked
          </Chip>
        </View>
      </Surface>

      {/* Quick Actions */}
      <Card style={styles.card}>
        <Card.Title title="Quick Actions" />
        <Card.Content>
          <View style={styles.buttonRow}>
            <TouchableOpacity 
              style={styles.actionButton}
              onPress={handleStartScan}>
              <Icon name="radar" size={32} color="#00a8ff" />
              <Text style={styles.actionText}>Start Scan</Text>
            </TouchableOpacity>
            <TouchableOpacity 
              style={styles.actionButton}
              onPress={handleUpdate}>
              <Icon name="update" size={32} color="#00a8ff" />
              <Text style={styles.actionText}>Update</Text>
            </TouchableOpacity>
            <TouchableOpacity 
              style={styles.actionButton}
              onPress={handleRefresh}>
              <Icon name="shield-refresh" size={32} color="#00a8ff" />
              <Text style={styles.actionText}>Refresh</Text>
            </TouchableOpacity>
          </View>
        </Card.Content>
      </Card>

      {/* Scan Status */}
      {scanStatus.isScanning && (
        <Card style={styles.card}>
          <Card.Title title="Scanning..." />
          <Card.Content>
            <ProgressBar 
              progress={scanStatus.progress / 100} 
              color="#00a8ff"
              style={styles.progressBar}
            />
            <Text style={styles.scanText}>
              {scanStatus.filesScanned} files scanned ({scanStatus.progress}%)
            </Text>
          </Card.Content>
        </Card>
      )}

      {/* System Metrics */}
      <Card style={styles.card}>
        <Card.Title title="System Health" />
        <Card.Content>
          <View style={styles.metricRow}>
            <Text style={styles.metricLabel}>CPU Usage</Text>
            <Text style={[styles.metricValue, {color: getStatusColor(metrics.cpu)}]}>
              {metrics.cpu}%
            </Text>
          </View>
          <ProgressBar 
            progress={metrics.cpu / 100} 
            color={getStatusColor(metrics.cpu)}
            style={styles.metricBar}
          />

          <View style={styles.metricRow}>
            <Text style={styles.metricLabel}>Memory Usage</Text>
            <Text style={[styles.metricValue, {color: getStatusColor(metrics.memory)}]}>
              {metrics.memory}%
            </Text>
          </View>
          <ProgressBar 
            progress={metrics.memory / 100} 
            color={getStatusColor(metrics.memory)}
            style={styles.metricBar}
          />

          <View style={styles.metricRow}>
            <Text style={styles.metricLabel}>Disk Usage</Text>
            <Text style={[styles.metricValue, {color: getStatusColor(metrics.disk)}]}>
              {metrics.disk}%
            </Text>
          </View>
          <ProgressBar 
            progress={metrics.disk / 100} 
            color={getStatusColor(metrics.disk)}
            style={styles.metricBar}
          />
        </Card.Content>
      </Card>

      {/* CPU Chart */}
      <Card style={styles.card}>
        <Card.Title title="CPU Usage (Last 5 Minutes)" />
        <Card.Content>
          <LineChart
            data={{
              labels: ['', '', '', '', '', ''],
              datasets: [{data: cpuHistory}],
            }}
            width={Dimensions.get('window').width - 80}
            height={180}
            yAxisSuffix="%"
            chartConfig={{
              backgroundColor: '#1e1e1e',
              backgroundGradientFrom: '#1e1e1e',
              backgroundGradientTo: '#2e2e2e',
              decimalPlaces: 0,
              color: (opacity = 1) => `rgba(0, 168, 255, ${opacity})`,
              labelColor: (opacity = 1) => `rgba(255, 255, 255, ${opacity})`,
              style: {borderRadius: 16},
              propsForDots: {r: '4', strokeWidth: '2', stroke: '#00a8ff'},
            }}
            bezier
            style={styles.chart}
          />
        </Card.Content>
      </Card>

      {/* Last Scan Info */}
      {metrics.lastScan && (
        <Card style={styles.card}>
          <Card.Title title="Last Scan" />
          <Card.Content>
            <Text style={styles.lastScanText}>
              Completed: {new Date(metrics.lastScan).toLocaleString()}
            </Text>
            <Text style={styles.lastScanText}>
              Threats Found: {metrics.threats}
            </Text>
          </Card.Content>
        </Card>
      )}

    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  headerCard: {
    margin: 16,
    padding: 16,
    borderRadius: 12,
  },
  headerContent: {
    gap: 12,
  },
  headerWithConnection: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 16,
  },
  statusText: {
    flex: 1,
  },
  statusTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
  },
  statusSubtitle: {
    fontSize: 14,
    color: '#666',
    marginTop: 4,
  },
  connectionIndicator: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingVertical: 4,
    paddingHorizontal: 10,
    backgroundColor: '#f5f5f5',
    borderRadius: 16,
  },
  connectionDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  connectionText: {
    fontSize: 11,
    color: '#666',
    fontWeight: '600',
  },
  threatChip: {
    alignSelf: 'flex-start',
  },
  card: {
    margin: 16,
    marginTop: 0,
  },
  buttonRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginTop: 8,
  },
  actionButton: {
    alignItems: 'center',
    padding: 12,
  },
  actionText: {
    marginTop: 8,
    fontSize: 12,
    color: '#333',
  },
  progressBar: {
    height: 8,
    borderRadius: 4,
  },
  scanText: {
    marginTop: 12,
    textAlign: 'center',
    fontSize: 14,
    color: '#666',
  },
  metricRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 16,
  },
  metricLabel: {
    fontSize: 16,
    color: '#333',
  },
  metricValue: {
    fontSize: 16,
    fontWeight: 'bold',
  },
  metricBar: {
    marginTop: 8,
    height: 6,
    borderRadius: 3,
  },
  chart: {
    marginVertical: 8,
    borderRadius: 16,
  },
  lastScanText: {
    fontSize: 14,
    color: '#666',
    marginTop: 8,
  },
});

export default DashboardScreen;
