import React, {useEffect, useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  Dimensions,
} from 'react-native';
import {Card, Surface, SegmentedButtons, Chip, useTheme} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import {LineChart, PieChart} from 'react-native-chart-kit';
import ApiService from '../services/ApiService';

interface NetworkConnection {
  protocol: string;
  localAddress: string;
  remoteAddress: string;
  state: string;
  pid: number;
  processName: string;
}

const NetworkMonitorScreen = (): JSX.Element => {
  const theme = useTheme();
  const [refreshing, setRefreshing] = useState(false);
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [networkSpeed, setNetworkSpeed] = useState({upload: 0, download: 0});
  const [bandwidth, setBandwidth] = useState({
    sent: 0,
    received: 0,
  });
  const [speedHistory, setSpeedHistory] = useState({
    upload: [0, 0, 0, 0, 0, 0],
    download: [0, 0, 0, 0, 0, 0],
  });
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    loadNetworkData();
    const interval = setInterval(loadNetworkData, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadNetworkData = async () => {
    const result = await ApiService.getSystemStatus();
    if (result.success && result.data) {
      // Mock network connections (in production, this would come from the backend)
      const mockConnections: NetworkConnection[] = [
        {
          protocol: 'TCP',
          localAddress: '192.168.0.100:54321',
          remoteAddress: '142.250.185.78:443',
          state: 'ESTABLISHED',
          pid: 1234,
          processName: 'chrome.exe',
        },
        {
          protocol: 'TCP',
          localAddress: '192.168.0.100:54322',
          remoteAddress: '104.244.42.129:443',
          state: 'ESTABLISHED',
          pid: 5678,
          processName: 'discord.exe',
        },
        {
          protocol: 'UDP',
          localAddress: '0.0.0.0:53',
          remoteAddress: '*:*',
          state: 'LISTENING',
          pid: 910,
          processName: 'dns.exe',
        },
      ];

      setConnections(mockConnections);

      // Mock network speed
      const upload = Math.random() * 100;
      const download = Math.random() * 500;
      setNetworkSpeed({upload, download});
      setSpeedHistory(prev => ({
        upload: [...prev.upload.slice(-5), upload],
        download: [...prev.download.slice(-5), download],
      }));

      // Mock bandwidth
      setBandwidth({
        sent: 1024 * 1024 * 1024 * 2.5, // 2.5 GB
        received: 1024 * 1024 * 1024 * 8.3, // 8.3 GB
      });
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadNetworkData();
    setRefreshing(false);
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes.toFixed(2)} B/s`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB/s`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB/s`;
  };

  const formatTotalBytes = (bytes: number) => {
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const getConnectionIcon = (protocol: string) => {
    return protocol === 'TCP' ? 'lan-connect' : 'wan';
  };

  const getStateColor = (state: string) => {
    switch (state) {
      case 'ESTABLISHED':
        return '#4caf50';
      case 'LISTENING':
        return '#2196f3';
      case 'TIME_WAIT':
        return '#ff9800';
      case 'CLOSE_WAIT':
        return '#f44336';
      default:
        return '#999';
    }
  };

  const filteredConnections = connections.filter(conn => {
    if (filter === 'all') return true;
    if (filter === 'tcp') return conn.protocol === 'TCP';
    if (filter === 'udp') return conn.protocol === 'UDP';
    return true;
  });

  const pieChartData = [
    {
      name: 'Download',
      population: bandwidth.received,
      color: '#4caf50',
      legendFontColor: '#333',
    },
    {
      name: 'Upload',
      population: bandwidth.sent,
      color: '#2196f3',
      legendFontColor: '#333',
    },
  ];

  return (
    <ScrollView
      style={[styles.container, {backgroundColor: theme.colors.background}]}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
      }>
      
      {/* Speed Card */}
      <Surface style={styles.speedCard} elevation={2}>
        <View style={styles.speedRow}>
          <View style={styles.speedItem}>
            <Icon name="arrow-up" size={32} color="#2196f3" />
            <Text style={styles.speedValue}>{formatBytes(networkSpeed.upload)}</Text>
            <Text style={styles.speedLabel}>Upload</Text>
          </View>
          <View style={styles.speedDivider} />
          <View style={styles.speedItem}>
            <Icon name="arrow-down" size={32} color="#4caf50" />
            <Text style={styles.speedValue}>{formatBytes(networkSpeed.download)}</Text>
            <Text style={styles.speedLabel}>Download</Text>
          </View>
        </View>
      </Surface>

      {/* Bandwidth Chart */}
      <Card style={styles.card}>
        <Card.Title title="Bandwidth Usage" />
        <Card.Content>
          <PieChart
            data={pieChartData}
            width={Dimensions.get('window').width - 80}
            height={180}
            chartConfig={{
              color: (opacity = 1) => `rgba(0, 0, 0, ${opacity})`,
            }}
            accessor="population"
            backgroundColor="transparent"
            paddingLeft="15"
            absolute
          />
          <View style={styles.bandwidthStats}>
            <View style={styles.bandwidthItem}>
              <Text style={styles.bandwidthLabel}>Total Sent</Text>
              <Text style={[styles.bandwidthValue, {color: '#2196f3'}]}>
                {formatTotalBytes(bandwidth.sent)}
              </Text>
            </View>
            <View style={styles.bandwidthItem}>
              <Text style={styles.bandwidthLabel}>Total Received</Text>
              <Text style={[styles.bandwidthValue, {color: '#4caf50'}]}>
                {formatTotalBytes(bandwidth.received)}
              </Text>
            </View>
          </View>
        </Card.Content>
      </Card>

      {/* Speed History */}
      <Card style={styles.card}>
        <Card.Title title="Network Speed History" />
        <Card.Content>
          <LineChart
            data={{
              labels: ['', '', '', '', '', ''],
              datasets: [
                {
                  data: speedHistory.download,
                  color: () => '#4caf50',
                },
                {
                  data: speedHistory.upload,
                  color: () => '#2196f3',
                },
              ],
              legend: ['Download', 'Upload'],
            }}
            width={Dimensions.get('window').width - 80}
            height={180}
            chartConfig={{
              backgroundColor: '#1e1e1e',
              backgroundGradientFrom: '#1e1e1e',
              backgroundGradientTo: '#2e2e2e',
              decimalPlaces: 0,
              color: (opacity = 1) => `rgba(255, 255, 255, ${opacity})`,
              labelColor: (opacity = 1) => `rgba(255, 255, 255, ${opacity})`,
              style: {borderRadius: 16},
            }}
            bezier
            style={styles.chart}
          />
        </Card.Content>
      </Card>

      {/* Active Connections */}
      <Card style={styles.card}>
        <Card.Title title="Active Connections" />
        <Card.Content>
          <SegmentedButtons
            value={filter}
            onValueChange={setFilter}
            buttons={[
              {value: 'all', label: 'All'},
              {value: 'tcp', label: 'TCP'},
              {value: 'udp', label: 'UDP'},
            ]}
            style={styles.segmentedButtons}
          />

          <View style={styles.connectionsList}>
            {filteredConnections.map((conn, index) => (
              <View key={index} style={styles.connectionItem}>
                <View style={styles.connectionHeader}>
                  <Icon
                    name={getConnectionIcon(conn.protocol)}
                    size={24}
                    color="#666"
                  />
                  <View style={styles.connectionInfo}>
                    <Text style={styles.processName}>{conn.processName}</Text>
                    <Text style={styles.connectionDetails}>
                      {conn.localAddress} → {conn.remoteAddress}
                    </Text>
                  </View>
                  <Chip
                    mode="flat"
                    textStyle={{color: getStateColor(conn.state), fontSize: 10}}
                    style={[
                      styles.stateChip,
                      {backgroundColor: `${getStateColor(conn.state)}20`},
                    ]}>
                    {conn.state}
                  </Chip>
                </View>
              </View>
            ))}
          </View>
        </Card.Content>
      </Card>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  speedCard: {
    margin: 16,
    padding: 16,
    borderRadius: 12,
  },
  speedRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
  },
  speedItem: {
    flex: 1,
    alignItems: 'center',
    gap: 8,
  },
  speedDivider: {
    width: 1,
    backgroundColor: '#e0e0e0',
    marginHorizontal: 16,
  },
  speedValue: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#333',
  },
  speedLabel: {
    fontSize: 12,
    color: '#666',
  },
  card: {
    margin: 16,
    marginTop: 0,
  },
  chart: {
    marginVertical: 8,
    borderRadius: 16,
  },
  bandwidthStats: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginTop: 16,
    paddingTop: 16,
    borderTopWidth: 1,
    borderTopColor: '#e0e0e0',
  },
  bandwidthItem: {
    alignItems: 'center',
  },
  bandwidthLabel: {
    fontSize: 12,
    color: '#666',
  },
  bandwidthValue: {
    fontSize: 18,
    fontWeight: 'bold',
    marginTop: 4,
  },
  segmentedButtons: {
    marginBottom: 16,
  },
  connectionsList: {
    gap: 12,
  },
  connectionItem: {
    padding: 12,
    backgroundColor: '#f9f9f9',
    borderRadius: 8,
    borderLeftWidth: 3,
    borderLeftColor: '#2196f3',
  },
  connectionHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  connectionInfo: {
    flex: 1,
  },
  processName: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#333',
  },
  connectionDetails: {
    fontSize: 11,
    color: '#666',
    marginTop: 4,
    fontFamily: 'monospace',
  },
  stateChip: {
    height: 24,
  },
});

export default NetworkMonitorScreen;
