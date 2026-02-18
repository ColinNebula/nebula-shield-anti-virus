import React, {useEffect, useState} from 'react';
import {View, Text, StyleSheet, FlatList, TouchableOpacity} from 'react-native';
import {Card, Button, Badge, Chip} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
// import {SocketService} from '../services/SocketService'; // Disabled - using HTTP API

interface Device {
  deviceId: string;
  deviceName: string;
  deviceType: 'desktop' | 'mobile';
  os: string;
  online: boolean;
  lastSeen: string;
}

const DevicesScreen = (): JSX.Element => {
  const [devices, setDevices] = useState<Device[]>([]);

  useEffect(() => {
    // Load devices
    loadDevices();

    // WebSocket disabled - using HTTP API
    // SocketService.on('device:connected', (data) => {
    //   loadDevices();
    // });

    // SocketService.on('device:disconnected', (data) => {
    //   loadDevices();
    // });

    return () => {
      // SocketService.off('device:connected');
      // SocketService.off('device:disconnected');
    };
  }, []);

  const loadDevices = async () => {
    // TODO: Fetch from API
    setDevices([
      {
        deviceId: 'desktop-001',
        deviceName: 'My Desktop PC',
        deviceType: 'desktop',
        os: 'Windows 11',
        online: true,
        lastSeen: new Date().toISOString(),
      },
      {
        deviceId: 'laptop-001',
        deviceName: 'Work Laptop',
        deviceType: 'desktop',
        os: 'Windows 10',
        online: false,
        lastSeen: new Date(Date.now() - 3600000).toISOString(),
      },
    ]);
  };

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'desktop':
        return 'desktop-tower';
      case 'mobile':
        return 'cellphone';
      default:
        return 'devices';
    }
  };

  const renderDevice = ({item}: {item: Device}) => (
    <Card style={styles.deviceCard}>
      <Card.Content>
        <View style={styles.deviceHeader}>
          <View style={styles.deviceInfo}>
            <Icon 
              name={getDeviceIcon(item.deviceType)} 
              size={40} 
              color={item.online ? '#4caf50' : '#999'}
            />
            <View style={styles.deviceText}>
              <Text style={styles.deviceName}>{item.deviceName}</Text>
              <Text style={styles.deviceOS}>{item.os}</Text>
            </View>
          </View>
          <Badge 
            style={[
              styles.statusBadge,
              {backgroundColor: item.online ? '#4caf50' : '#999'},
            ]}>
            {item.online ? 'Online' : 'Offline'}
          </Badge>
        </View>

        <View style={styles.deviceActions}>
          <Chip 
            icon="clock-outline" 
            mode="outlined" 
            style={styles.chip}>
            Last seen: {new Date(item.lastSeen).toLocaleTimeString()}
          </Chip>
        </View>

        {item.online && (
          <View style={styles.actionButtons}>
            <Button 
              mode="contained-tonal" 
              icon="radar"
              onPress={() => handleStartScan(item.deviceId)}
              style={styles.actionButton}>
              Scan
            </Button>
            <Button 
              mode="contained-tonal" 
              icon="update"
              style={styles.actionButton}>
              Update
            </Button>
          </View>
        )}
      </Card.Content>
    </Card>
  );

  const handleStartScan = (deviceId: string) => {
    // WebSocket disabled - using HTTP API
    // SocketService.emit('command:execute', {
    //   targetDeviceId: deviceId,
    //   command: 'start-scan',
    //   params: {type: 'quick'},
    // });
    console.log('Scan feature requires HTTP API implementation');
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>My Devices</Text>
        <Text style={styles.headerSubtitle}>
          {devices.filter(d => d.online).length} online • {devices.length} total
        </Text>
      </View>

      <FlatList
        data={devices}
        renderItem={renderDevice}
        keyExtractor={item => item.deviceId}
        contentContainerStyle={styles.list}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    padding: 16,
    backgroundColor: '#fff',
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#333',
  },
  headerSubtitle: {
    fontSize: 14,
    color: '#666',
    marginTop: 4,
  },
  list: {
    padding: 16,
  },
  deviceCard: {
    marginBottom: 16,
  },
  deviceHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  deviceInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  deviceText: {
    gap: 4,
  },
  deviceName: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#333',
  },
  deviceOS: {
    fontSize: 14,
    color: '#666',
  },
  statusBadge: {
    paddingHorizontal: 8,
  },
  deviceActions: {
    marginTop: 12,
  },
  chip: {
    alignSelf: 'flex-start',
  },
  actionButtons: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 12,
  },
  actionButton: {
    flex: 1,
  },
});

export default DevicesScreen;
