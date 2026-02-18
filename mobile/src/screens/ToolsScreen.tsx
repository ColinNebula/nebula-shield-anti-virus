import React, {useState, useEffect} from 'react';
import {View, StyleSheet, ScrollView, RefreshControl, Alert} from 'react-native';
import {SegmentedButtons, useTheme, Card, Button, Text, List, ActivityIndicator} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import ApiService from '../services/ApiService';
import WebProtectionScreen from './WebProtectionScreen';
import VPNScreen from './VPNScreen';
import TestBrowserScreen from './TestBrowserScreen';
import SecureBrowserScreen from './SecureBrowserScreen';

const ToolsScreen = (): JSX.Element => {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState('quarantine');
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  
  // Quarantine state
  const [quarantineFiles, setQuarantineFiles] = useState([]);
  const [quarantineStats, setQuarantineStats] = useState({totalFiles: 0, totalSize: 0});
  
  // Disk cleanup state
  const [diskResults, setDiskResults] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [cleaning, setCleaning] = useState(null);

  console.log('ToolsScreen rendering, activeTab:', activeTab);

  useEffect(() => {
    if (activeTab === 'quarantine') {
      loadQuarantineData();
    } else if (activeTab === 'cleanup') {
      loadDiskData();
    }
    // Web protection and VPN load their own data
  }, [activeTab]);

  const loadQuarantineData = async () => {
    setLoading(true);
    try {
      const filesResult = await ApiService.getQuarantinedFiles();
      if (filesResult.success) {
        // Ensure we always set an array, even if data is undefined or not an array
        const files = Array.isArray(filesResult.data) ? filesResult.data : [];
        setQuarantineFiles(files);
        
        // Get stats from the files
        const totalFiles = files.length || 0;
        const totalSize = files.reduce((sum: number, file: any) => sum + (file.size || 0), 0) || 0;
        setQuarantineStats({ totalFiles, totalSize });
      } else {
        // If request fails, reset to empty array
        setQuarantineFiles([]);
        setQuarantineStats({ totalFiles: 0, totalSize: 0 });
      }
    } catch (error) {
      console.error('Error loading quarantine data:', error);
      setQuarantineFiles([]);
      setQuarantineStats({ totalFiles: 0, totalSize: 0 });
    }
    setLoading(false);
  };

  const loadDiskData = async () => {
    setLoading(true);
    try {
      // Disk results are loaded after analysis
      // Initialize with null to show analyze button
      setDiskResults(null);
    } catch (error) {
      console.error('Error loading disk data:', error);
    }
    setLoading(false);
  };

  const onRefresh = async () => {
    setRefreshing(true);
    if (activeTab === 'quarantine') {
      await loadQuarantineData();
    } else if (activeTab === 'cleanup') {
      await loadDiskData();
    }
    setRefreshing(false);
  };

  const handleAnalyzeDisk = async () => {
    setAnalyzing(true);
    const result = await ApiService.analyzeDisk();
    if (result.success) {
      setDiskResults(result.data);
      Alert.alert('Analysis Complete', `Found ${result.data?.totalSpace || 0} MB that can be freed`);
    } else {
      Alert.alert('Error', result.error || 'Failed to analyze disk');
    }
    setAnalyzing(false);
  };

  const handleCleanCategory = async (category: string) => {
    setCleaning(category);
    const result = await ApiService.cleanDiskCategory(category);
    if (result.success) {
      Alert.alert('Success', `Cleaned ${category} successfully`);
      await loadDiskData();
    } else {
      Alert.alert('Error', result.error || 'Failed to clean category');
    }
    setCleaning(null);
  };

  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const handleRestoreFile = async (fileId: string) => {
    Alert.alert(
      'Restore File',
      'Are you sure you want to restore this file to its original location?',
      [
        {text: 'Cancel', style: 'cancel'},
        {
          text: 'Restore',
          onPress: async () => {
            const result = await ApiService.restoreFile(fileId);
            if (result.success) {
              Alert.alert('Success', 'File restored successfully');
              await loadQuarantineData();
            } else {
              Alert.alert('Error', result.error || 'Failed to restore file');
            }
          },
        },
      ]
    );
  };

  const handleDeleteFile = async (fileId: string) => {
    Alert.alert(
      'Delete File',
      'Are you sure you want to permanently delete this file? This action cannot be undone.',
      [
        {text: 'Cancel', style: 'cancel'},
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            const result = await ApiService.deleteFile(fileId);
            if (result.success) {
              Alert.alert('Success', 'File deleted successfully');
              await loadQuarantineData();
            } else {
              Alert.alert('Error', result.error || 'Failed to delete file');
            }
          },
        },
      ]
    );
  };

  return (
    <View style={[styles.container, {backgroundColor: theme.colors.background}]}>
      <View style={[styles.header, {backgroundColor: theme.colors.surface, borderBottomColor: theme.colors.outline}]}>
        <SegmentedButtons
          value={activeTab}
          onValueChange={(value) => {
            console.log('Tab changed to:', value);
            setActiveTab(value);
          }}
          buttons={[
            {
              value: 'quarantine',
              label: 'Files',
              icon: 'file-lock',
            },
            {
              value: 'cleanup',
              label: 'Clean',
              icon: 'broom',
            },
            {
              value: 'browser',
              label: 'Browser',
              icon: 'shield-search',
            },
            {
              value: 'webshield',
              label: 'Web',
              icon: 'web',
            },
            {
              value: 'vpn',
              label: 'VPN',
              icon: 'shield-lock',
            },
          ]}
          style={styles.segmentedButtons}
        />
      </View>
      <ScrollView 
        style={styles.content} 
        contentContainerStyle={{ flexGrow: 1 }}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}>
        
        {activeTab === 'browser' ? (
          <SecureBrowserScreen standalone={false} />
        ) : activeTab === 'webshield' ? (
          <WebProtectionScreen />
        ) : activeTab === 'vpn' ? (
          <VPNScreen />
        ) : loading ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" />
            <Text style={{marginTop: 16}}>Loading...</Text>
          </View>
        ) : activeTab === 'quarantine' ? (
          <View style={styles.tabContent}>
            <Card style={styles.card}>
              <Card.Content>
                <View style={styles.iconHeader}>
                  <Icon name="file-lock" size={48} color="#f44336" />
                  <Text variant="headlineSmall" style={{marginTop: 8}}>Quarantine Manager</Text>
                  <Text variant="bodyMedium" style={{marginTop: 8, color: theme.colors.onSurfaceVariant}}>
                    {quarantineStats.totalFiles} files • {formatSize(quarantineStats.totalSize)}
                  </Text>
                </View>
              </Card.Content>
            </Card>
            
            {!Array.isArray(quarantineFiles) || quarantineFiles.length === 0 ? (
              <Card style={styles.card}>
                <Card.Content>
                  <View style={styles.emptyState}>
                    <Icon name="shield-check" size={64} color="#4caf50" />
                    <Text style={{marginTop: 16, textAlign: 'center', color: theme.colors.onSurfaceVariant}}>
                      All clear! No threats in quarantine.
                    </Text>
                  </View>
                </Card.Content>
              </Card>
            ) : (
              quarantineFiles.map((file: any) => (
                <Card key={file.id} style={styles.card}>
                  <Card.Title 
                    title={file.fileName || file.name} 
                    subtitle={file.threatName || 'Unknown Threat'}
                    left={props => <Icon name="file-lock" size={24} {...props} />}
                  />
                  <Card.Content>
                    <Text variant="bodySmall">Path: {file.originalPath || file.path}</Text>
                    <Text variant="bodySmall">Size: {formatSize(file.fileSize || file.size || 0)}</Text>
                  </Card.Content>
                  <Card.Actions>
                    <Button onPress={() => handleRestoreFile(file.id)}>Restore</Button>
                    <Button textColor="#f44336" onPress={() => handleDeleteFile(file.id)}>Delete</Button>
                  </Card.Actions>
                </Card>
              ))
            )}
            
            <Card style={styles.card}>
              <Card.Title title="About Quarantine" />
              <Card.Content>
                <List.Item
                  title="Isolated Threats"
                  description="Files detected as threats are safely isolated"
                  left={props => <Icon name="lock" size={24} {...props} />}
                />
                <List.Item
                  title="Restore Option"
                  description="False positives can be restored to original location"
                  left={props => <Icon name="restore" size={24} {...props} />}
                />
                <List.Item
                  title="Permanent Deletion"
                  description="Confirmed threats can be permanently removed"
                  left={props => <Icon name="delete-forever" size={24} {...props} />}
                />
              </Card.Content>
            </Card>
          </View>
        ) : (
          <View style={styles.tabContent}>
            <Card style={styles.card}>
              <Card.Content>
                <View style={styles.iconHeader}>
                  <Icon name="broom" size={48} color="#ff9800" />
                  <Text variant="headlineSmall" style={{marginTop: 8}}>Disk Cleanup</Text>
                  {diskResults && (
                    <Text variant="bodyMedium" style={{marginTop: 8, color: theme.colors.onSurfaceVariant}}>
                      {formatSize(diskResults.totalSpace || 0)} can be freed
                    </Text>
                  )}
                </View>
                <Button 
                  mode="contained" 
                  icon="magnify-scan" 
                  onPress={handleAnalyzeDisk}
                  loading={analyzing}
                  disabled={analyzing}
                  style={{marginTop: 16}}>
                  {analyzing ? 'Analyzing...' : 'Analyze Disk'}
                </Button>
              </Card.Content>
            </Card>
            
            {diskResults && diskResults.categories && (
              <Card style={styles.card}>
                <Card.Title title="Cleanup Categories" />
                <Card.Content>
                  {diskResults.categories.map((cat: any) => (
                    <List.Item
                      key={cat.name}
                      title={cat.displayName || cat.name}
                      description={`${cat.fileCount} files • ${formatSize(cat.totalSize || 0)}`}
                      left={props => <Icon name={cat.icon || 'file'} size={24} {...props} />}
                      right={props => (
                        <Button 
                          mode="outlined" 
                          compact
                          loading={cleaning === cat.name}
                          disabled={cleaning !== null}
                          onPress={() => handleCleanCategory(cat.name)}>
                          Clean
                        </Button>
                      )}
                    />
                  ))}
                </Card.Content>
              </Card>
            )}
            
            {!diskResults && (
              <Card style={styles.card}>
                <Card.Title title="Cleanup Categories" />
                <Card.Content>
                  <List.Item
                    title="Temporary Files"
                    description="Clear system temp files"
                    left={props => <Icon name="file-clock" size={24} {...props} />}
                  />
                  <List.Item
                    title="Browser Cache"
                    description="Remove cached web data"
                    left={props => <Icon name="web" size={24} {...props} />}
                  />
                  <List.Item
                    title="Windows Update Files"
                    description="Old update installation files"
                    left={props => <Icon name="microsoft-windows" size={24} {...props} />}
                  />
                  <List.Item
                    title="Recycle Bin"
                    description="Empty deleted files"
                    left={props => <Icon name="delete" size={24} {...props} />}
                  />
                  <List.Item
                    title="Downloads Folder"
                    description="Old downloaded files"
                    left={props => <Icon name="download" size={24} {...props} />}
                  />
                  <Text variant="bodySmall" style={{marginTop: 16, color: theme.colors.onSurfaceVariant}}>
                    Tap "Analyze Disk" to scan for junk files
                  </Text>
                </Card.Content>
              </Card>
            )}
            
            <Card style={styles.card}>
              <Card.Title title="Safety Notice" />
              <Card.Content>
                <Text variant="bodySmall" style={{color: theme.colors.onSurfaceVariant}}>
                  All cleanup operations are safe and won't remove important system files or personal data.
                </Text>
              </Card.Content>
            </Card>
          </View>
        )}
      </ScrollView>
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
  segmentedButtons: {
    // Ensure all buttons are visible on small screens
  },
  content: {
    flex: 1,
  },
  tabContent: {
    padding: 16,
  },
  card: {
    marginBottom: 16,
  },
  iconHeader: {
    alignItems: 'center',
    paddingVertical: 16,
  },
  emptyState: {
    alignItems: 'center',
    paddingVertical: 32,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 32,
  },
});

export default ToolsScreen;
