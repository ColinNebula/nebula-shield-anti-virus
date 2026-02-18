import React, {useEffect, useState, useRef} from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  RefreshControl,
  TouchableOpacity,
  Alert,
  ScrollView,
  Animated,
} from 'react-native';
import {Card, Button, Chip, FAB, Portal, Dialog, RadioButton, Snackbar, useTheme, ProgressBar, List, Divider} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import ApiService from '../services/ApiService';
import { MalwareScannerService, ScanResult, ThreatDetection } from '../services/MalwareScannerService';
import { SMSCallProtectionService } from '../services/SMSCallProtectionService';
import { AntiTheftService } from '../services/AntiTheftService';

interface ScanRecord {
  id: string;
  type: 'quick' | 'full' | 'custom';
  status: 'completed' | 'scanning' | 'failed';
  filesScanned: number;
  threatsFound: number;
  duration: number;
  timestamp: string;
  deviceId: string;
}

const ScansScreen = (): JSX.Element => {
  const theme = useTheme();
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [dialogVisible, setDialogVisible] = useState(false);
  const [scanType, setScanType] = useState('quick');
  const [snackbarVisible, setSnackbarVisible] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const statusPollIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const [currentScan, setCurrentScan] = useState<{
    isScanning: boolean;
    progress: number;
    filesScanned: number;
  }>({
    isScanning: false,
    progress: 0,
    filesScanned: 0,
  });

  useEffect(() => {
    loadScanHistory();
    
    return () => {
      // Clean up polling interval on unmount
      if (statusPollIntervalRef.current) {
        clearInterval(statusPollIntervalRef.current);
      }
    };
  }, []);

  const loadScanHistory = async () => {
    // Prevent overlapping requests
    if (isLoadingHistory) {
      console.log('Skipping scan history request - previous request still pending');
      return;
    }

    setIsLoadingHistory(true);
    try {
      const result = await ApiService.getScanHistory();
      if (result.success && result.data) {
        // Convert API response to scan records
        const scanRecords: ScanRecord[] = result.data.scans?.map((scan: any) => ({
          id: scan.id || Date.now().toString(),
          type: scan.type || 'quick',
          status: scan.status || 'completed',
          filesScanned: scan.filesScanned || 0,
          threatsFound: scan.threatsFound || 0,
          duration: scan.duration || 0,
          timestamp: scan.timestamp || new Date().toISOString(),
          deviceId: 'desktop-001',
        })) || [];
        setScans(scanRecords);
      }
    } finally {
      setIsLoadingHistory(false);
    }
  };

  // Poll for scan status updates
  const startStatusPolling = () => {
    // Clear any existing interval
    if (statusPollIntervalRef.current) {
      clearInterval(statusPollIntervalRef.current);
    }

    statusPollIntervalRef.current = setInterval(async () => {
      const result = await ApiService.getScanStatus();
      if (result.success && result.data) {
        const { isScanning, progress, filesScanned } = result.data;
        setCurrentScan({ isScanning, progress, filesScanned });
        
        if (!isScanning && statusPollIntervalRef.current) {
          clearInterval(statusPollIntervalRef.current);
          statusPollIntervalRef.current = null;
          await loadScanHistory();
          setSnackbarMessage('Scan completed!');
          setSnackbarVisible(true);
        }
      }
    }, 3000); // Poll every 3 seconds (increased from 2 to reduce load)
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadScanHistory();
    setRefreshing(false);
  };

  const handleStartScan = async () => {
    setDialogVisible(false);
    setSnackbarMessage(`Starting ${scanType} scan...`);
    setSnackbarVisible(true);
    
    const result = await ApiService.startScan(scanType as any);
    
    if (result.success) {
      setCurrentScan({
        isScanning: true,
        progress: 0,
        filesScanned: 0,
      });
      setSnackbarMessage('Scan started successfully!');
      setSnackbarVisible(true);
      
      // Poll for scan status
      startStatusPolling();
    } else {
      // Check if scan is already in progress
      if (result.error && (
        result.error.includes('already in progress') || 
        result.error.includes('Scan already in progress')
      )) {
        Alert.alert(
          'Scan Already Running',
          'A scan is currently in progress. Please wait for it to complete before starting a new one.',
          [
            { text: 'OK' },
            { 
              text: 'View Progress', 
              onPress: () => {
                // Ensure polling is active
                if (!statusPollIntervalRef.current) {
                  startStatusPolling();
                }
              }
            }
          ]
        );
      } else {
        Alert.alert('Scan Failed', result.error || 'Failed to start scan');
      }
    }
  };

  const getScanIcon = (type: string) => {
    switch (type) {
      case 'full':
        return 'shield-search';
      case 'quick':
        return 'shield-check';
      case 'custom':
        return 'shield-edit';
      default:
        return 'shield';
    }
  };

  const getScanColor = (status: string) => {
    switch (status) {
      case 'completed':
        return '#4caf50';
      case 'scanning':
        return '#2196f3';
      case 'failed':
        return '#f44336';
      default:
        return '#999';
    }
  };

  const formatDuration = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  };

  const renderScan = ({item}: {item: ScanRecord}) => (
    <Card style={styles.scanCard}>
      <Card.Content>
        <View style={styles.scanHeader}>
          <Icon
            name={getScanIcon(item.type)}
            size={32}
            color={getScanColor(item.status)}
          />
          <View style={styles.scanInfo}>
            <Text style={styles.scanType}>
              {item.type.charAt(0).toUpperCase() + item.type.slice(1)} Scan
            </Text>
            <Text style={styles.scanDate}>
              {new Date(item.timestamp).toLocaleString()}
            </Text>
          </View>
          <Chip
            icon={item.status === 'completed' ? 'check-circle' : 'alert-circle'}
            mode="flat"
            textStyle={{color: getScanColor(item.status)}}
            style={[
              styles.statusChip,
              {backgroundColor: `${getScanColor(item.status)}20`},
            ]}>
            {item.status}
          </Chip>
        </View>

        <View style={styles.scanStats}>
          <View style={styles.stat}>
            <Icon name="file-document" size={20} color="#666" />
            <Text style={styles.statText}>{item.filesScanned} files</Text>
          </View>
          <View style={styles.stat}>
            <Icon
              name={item.threatsFound > 0 ? 'alert' : 'check'}
              size={20}
              color={item.threatsFound > 0 ? '#f44336' : '#4caf50'}
            />
            <Text style={styles.statText}>{item.threatsFound} threats</Text>
          </View>
          <View style={styles.stat}>
            <Icon name="clock-outline" size={20} color="#666" />
            <Text style={styles.statText}>{formatDuration(item.duration)}</Text>
          </View>
        </View>
      </Card.Content>
    </Card>
  );

  return (
    <View style={[styles.container, {backgroundColor: theme.colors.background}]}>
      <View style={[styles.header, {backgroundColor: theme.colors.surface, borderBottomColor: theme.colors.outline}]}>
        <Text style={[styles.headerTitle, {color: theme.colors.onSurface}]}>Scan History</Text>
        <Text style={[styles.headerSubtitle, {color: theme.colors.onSurfaceVariant}]}>
          Monitor and manage security scans
        </Text>
      </View>

      {currentScan.isScanning && (
        <Card style={styles.currentScanCard}>
          <Card.Content>
            <View style={styles.currentScanHeader}>
              <Icon name="radar" size={32} color="#2196f3" />
              <View style={styles.currentScanInfo}>
                <Text style={styles.currentScanTitle}>Scanning...</Text>
                <Text style={styles.currentScanProgress}>
                  {currentScan.progress}% • {currentScan.filesScanned} files scanned
                </Text>
              </View>
            </View>
            <View style={styles.progressBar}>
              <View
                style={[
                  styles.progressFill,
                  {width: `${currentScan.progress}%`},
                ]}
              />
            </View>
          </Card.Content>
        </Card>
      )}

      {scans.length === 0 ? (
        <View style={styles.emptyState}>
          <Icon name="shield-search" size={80} color="#ccc" />
          <Text style={styles.emptyTitle}>No Scans Yet</Text>
          <Text style={styles.emptySubtitle}>
            Start your first scan to protect your devices
          </Text>
          <Button
            mode="contained"
            icon="radar"
            onPress={() => setDialogVisible(true)}
            style={styles.emptyButton}>
            Start Scan
          </Button>
        </View>
      ) : (
        <FlatList
          data={scans}
          renderItem={renderScan}
          keyExtractor={(item) => item.id}
          refreshControl={
            <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
          }
          contentContainerStyle={styles.listContent}
        />
      )}

      <FAB
        style={styles.fab}
        icon="radar"
        onPress={() => setDialogVisible(true)}
      />

      <Portal>
        <Dialog visible={dialogVisible} onDismiss={() => setDialogVisible(false)}>
          <Dialog.Title>Start Security Scan</Dialog.Title>
          <Dialog.Content>
            <Text style={styles.dialogText}>Choose scan type:</Text>
            <RadioButton.Group
              onValueChange={(value) => setScanType(value)}
              value={scanType}>
              <View style={styles.radioOption}>
                <RadioButton value="quick" />
                <View style={styles.radioLabel}>
                  <Text style={styles.radioTitle}>Quick Scan</Text>
                  <Text style={styles.radioSubtitle}>
                    Scan common threat locations (~5 mins)
                  </Text>
                </View>
              </View>
              <View style={styles.radioOption}>
                <RadioButton value="full" />
                <View style={styles.radioLabel}>
                  <Text style={styles.radioTitle}>Full Scan</Text>
                  <Text style={styles.radioSubtitle}>
                    Deep scan of entire system (~1 hour)
                  </Text>
                </View>
              </View>
              <View style={styles.radioOption}>
                <RadioButton value="custom" />
                <View style={styles.radioLabel}>
                  <Text style={styles.radioTitle}>Custom Scan</Text>
                  <Text style={styles.radioSubtitle}>
                    Scan specific folders
                  </Text>
                </View>
              </View>
            </RadioButton.Group>
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setDialogVisible(false)}>Cancel</Button>
            <Button onPress={handleStartScan} mode="contained">
              Start
            </Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>

      <Snackbar
        visible={snackbarVisible}
        onDismiss={() => setSnackbarVisible(false)}
        duration={3000}
        action={{
          label: 'OK',
          onPress: () => setSnackbarVisible(false),
        }}>
        {snackbarMessage}
      </Snackbar>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  header: {
    padding: 16,
    borderBottomWidth: 1,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: 'bold',
  },
  headerSubtitle: {
    fontSize: 14,
    marginTop: 4,
  },
  currentScanCard: {
    margin: 16,
    backgroundColor: '#e3f2fd',
  },
  currentScanHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 12,
  },
  currentScanInfo: {
    flex: 1,
  },
  currentScanTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#2196f3',
  },
  currentScanProgress: {
    fontSize: 14,
    color: '#666',
    marginTop: 4,
  },
  progressBar: {
    height: 8,
    backgroundColor: '#e0e0e0',
    borderRadius: 4,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#2196f3',
  },
  list: {
    padding: 16,
    paddingBottom: 80,
  },
  scanCard: {
    marginBottom: 16,
  },
  scanHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 12,
  },
  scanInfo: {
    flex: 1,
  },
  scanType: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#333',
  },
  scanDate: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  statusChip: {
    height: 28,
  },
  scanStats: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    paddingTop: 12,
    borderTopWidth: 1,
    borderTopColor: '#e0e0e0',
  },
  stat: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  statText: {
    fontSize: 14,
    color: '#666',
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
    textAlign: 'center',
  },
  emptyButton: {
    marginTop: 24,
  },
  listContent: {
    paddingBottom: 80,
  },
  fab: {
    position: 'absolute',
    right: 16,
    bottom: 16,
    backgroundColor: '#2196f3',
  },
  dialogText: {
    fontSize: 14,
    color: '#666',
    marginBottom: 16,
  },
  radioOption: {
    flexDirection: 'row',
    alignItems: 'center',
    marginVertical: 8,
  },
  radioLabel: {
    flex: 1,
    marginLeft: 8,
  },
  radioTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#333',
  },
  radioSubtitle: {
    fontSize: 12,
    color: '#666',
    marginTop: 2,
  },
});

export default ScansScreen;
