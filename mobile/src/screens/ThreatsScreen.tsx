import React, {useEffect, useState} from 'react';
import {View, Text, StyleSheet, FlatList} from 'react-native';
import {Card, Chip, Button} from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import {SocketService} from '../services/SocketService';

interface Threat {
  id: string;
  threatName: string;
  filePath: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  action: 'quarantined' | 'deleted' | 'blocked';
  timestamp: string;
  deviceId: string;
}

const ThreatsScreen = (): JSX.Element => {
  const [threats, setThreats] = useState<Threat[]>([]);

  useEffect(() => {
    // Listen for threat alerts
    SocketService.on('threat:alert', (data) => {
      const newThreat: Threat = {
        id: Date.now().toString(),
        threatName: data.threatName,
        filePath: data.filePath,
        severity: data.severity,
        action: data.action,
        timestamp: new Date().toISOString(),
        deviceId: data.sourceDevice,
      };
      setThreats(prev => [newThreat, ...prev]);
    });

    return () => {
      SocketService.off('threat:alert');
    };
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return '#d32f2f';
      case 'high':
        return '#f44336';
      case 'medium':
        return '#ff9800';
      case 'low':
        return '#ffc107';
      default:
        return '#999';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'alert-octagon';
      case 'medium':
        return 'alert';
      case 'low':
        return 'alert-circle-outline';
      default:
        return 'information-outline';
    }
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case 'quarantined':
        return '#ff9800';
      case 'deleted':
        return '#f44336';
      case 'blocked':
        return '#4caf50';
      default:
        return '#999';
    }
  };

  const renderThreat = ({item}: {item: Threat}) => (
    <Card style={styles.threatCard}>
      <Card.Content>
        <View style={styles.threatHeader}>
          <Icon 
            name={getSeverityIcon(item.severity)} 
            size={32} 
            color={getSeverityColor(item.severity)}
          />
          <View style={styles.threatInfo}>
            <Text style={styles.threatName}>{item.threatName}</Text>
            <Text style={styles.threatPath} numberOfLines={1}>
              {item.filePath}
            </Text>
          </View>
        </View>

        <View style={styles.threatMeta}>
          <Chip 
            icon="shield-alert" 
            mode="flat"
            textStyle={{color: getSeverityColor(item.severity)}}
            style={[styles.chip, {backgroundColor: `${getSeverityColor(item.severity)}20`}]}>
            {item.severity.toUpperCase()}
          </Chip>
          <Chip 
            icon="check-circle" 
            mode="flat"
            textStyle={{color: getActionColor(item.action)}}
            style={[styles.chip, {backgroundColor: `${getActionColor(item.action)}20`}]}>
            {item.action}
          </Chip>
        </View>

        <Text style={styles.timestamp}>
          {new Date(item.timestamp).toLocaleString()}
        </Text>

        <View style={styles.actions}>
          <Button 
            mode="text" 
            icon="information"
            onPress={() => {}}>
            Details
          </Button>
          <Button 
            mode="text" 
            icon="delete"
            textColor="#f44336"
            onPress={() => {}}>
            Remove
          </Button>
        </View>
      </Card.Content>
    </Card>
  );

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <View style={styles.headerRow}>
          <Text style={styles.headerTitle}>Threat Monitor</Text>
          <Chip icon="alert-circle" mode="flat" style={styles.countChip}>
            {threats.length}
          </Chip>
        </View>
        <Text style={styles.headerSubtitle}>
          Real-time threat detection and quarantine
        </Text>
      </View>

      {threats.length === 0 ? (
        <View style={styles.emptyState}>
          <Icon name="shield-check" size={80} color="#4caf50" />
          <Text style={styles.emptyTitle}>No Threats Detected</Text>
          <Text style={styles.emptySubtitle}>
            Your devices are protected
          </Text>
        </View>
      ) : (
        <FlatList
          data={threats}
          renderItem={renderThreat}
          keyExtractor={item => item.id}
          contentContainerStyle={styles.list}
        />
      )}
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
  headerRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
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
  countChip: {
    backgroundColor: '#ff525220',
  },
  list: {
    padding: 16,
  },
  threatCard: {
    marginBottom: 16,
  },
  threatHeader: {
    flexDirection: 'row',
    gap: 12,
    marginBottom: 12,
  },
  threatInfo: {
    flex: 1,
  },
  threatName: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#333',
  },
  threatPath: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  threatMeta: {
    flexDirection: 'row',
    gap: 8,
    marginVertical: 8,
  },
  chip: {
    height: 28,
  },
  timestamp: {
    fontSize: 12,
    color: '#999',
    marginTop: 8,
  },
  actions: {
    flexDirection: 'row',
    justifyContent: 'flex-end',
    marginTop: 8,
  },
  emptyState: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 32,
  },
  emptyTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#333',
    marginTop: 16,
  },
  emptySubtitle: {
    fontSize: 14,
    color: '#666',
    marginTop: 8,
  },
});

export default ThreatsScreen;
