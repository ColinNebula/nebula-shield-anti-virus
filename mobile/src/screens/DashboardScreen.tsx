import React, {useEffect, useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  TouchableOpacity,
  Dimensions,
} from 'react-native';
import {Card, Button, ProgressBar, Chip, Surface} from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import {LineChart} from 'react-native-chart-kit';
import {SocketService} from '../services/SocketService';

const DashboardScreen = (): JSX.Element => {
  const [refreshing, setRefreshing] = useState(false);
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

  useEffect(() => {
    // Listen for real-time metrics from desktop
    SocketService.on('metrics:data', (data) => {
      setMetrics({
        cpu: data.cpu || 0,
        memory: data.memory || 0,
        disk: data.disk || 0,
        threats: data.threatsFound || 0,
        lastScan: data.lastScan,
      });

      // Update CPU history
      setCpuHistory(prev => [...prev.slice(-5), data.cpu || 0]);
    });

    // Listen for scan updates
    SocketService.on('scan:update', (data) => {
      setScanStatus({
        isScanning: data.status === 'scanning',
        progress: data.progress || 0,
        filesScanned: data.filesScanned || 0,
      });
    });

    // Listen for threat alerts
    SocketService.on('threat:alert', (data) => {
      setMetrics(prev => ({...prev, threats: prev.threats + 1}));
      // TODO: Show push notification
    });

    return () => {
      SocketService.off('metrics:data');
      SocketService.off('scan:update');
      SocketService.off('threat:alert');
    };
  }, []);

  const onRefresh = () => {
    setRefreshing(true);
    // Request latest data from desktop
    SocketService.emit('request:metrics', {});
    setTimeout(() => setRefreshing(false), 1000);
  };

  const handleStartScan = () => {
    SocketService.emit('command:execute', {
      targetDeviceId: 'desktop-001', // TODO: Get from device list
      command: 'start-scan',
      params: {type: 'quick'},
    });
  };

  const getStatusColor = (value: number) => {
    if (value < 50) return '#4caf50';
    if (value < 80) return '#ff9800';
    return '#f44336';
  };

  return (
    <ScrollView
      style={styles.container}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
      }>
      
      {/* Status Header */}
      <Surface style={styles.headerCard} elevation={2}>
        <View style={styles.headerContent}>
          <View style={styles.statusRow}>
            <Icon name="shield-check" size={40} color="#4caf50" />
            <View style={styles.statusText}>
              <Text style={styles.statusTitle}>Protected</Text>
              <Text style={styles.statusSubtitle}>All systems operational</Text>
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
            <TouchableOpacity style={styles.actionButton}>
              <Icon name="update" size={32} color="#00a8ff" />
              <Text style={styles.actionText}>Update</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.actionButton}>
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
    backgroundColor: '#f5f5f5',
  },
  headerCard: {
    margin: 16,
    padding: 16,
    borderRadius: 12,
  },
  headerContent: {
    gap: 12,
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
