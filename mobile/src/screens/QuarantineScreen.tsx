import React, {useEffect, useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  RefreshControl,
  Alert,
} from 'react-native';
import {Card, Button, Chip, IconButton, Surface, Snackbar, useTheme} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import ApiService from '../services/ApiService';

interface QuarantinedFile {
  id: string;
  fileName: string;
  originalPath: string;
  threatName: string;
  threatType: string;
  dateQuarantined: string;
  fileSize: number;
}

const QuarantineScreen = (): JSX.Element => {
  const theme = useTheme();
  const [files, setFiles] = useState<QuarantinedFile[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [stats, setStats] = useState({totalFiles: 0, totalSize: 0});
  const [snackbarVisible, setSnackbarVisible] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');

  useEffect(() => {
    loadQuarantineData();
  }, []);

  const loadQuarantineData = async () => {
    // Load quarantined files
    const filesResult = await ApiService.request('/quarantine');
    if (filesResult.success && filesResult.data) {
      setFiles(filesResult.data.files || []);
    }

    // Load stats
    const statsResult = await ApiService.request('/quarantine/stats');
    if (statsResult.success && statsResult.data) {
      setStats(statsResult.data);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadQuarantineData();
    setRefreshing(false);
  };

  const handleRestore = async (fileId: string, fileName: string) => {
    Alert.alert(
      'Restore File',
      `Are you sure you want to restore "${fileName}"? This file may be harmful.`,
      [
        {text: 'Cancel', style: 'cancel'},
        {
          text: 'Restore',
          style: 'destructive',
          onPress: async () => {
            const result = await ApiService.request(`/quarantine/${fileId}/restore`, {
              method: 'POST',
            });
            if (result.success) {
              setSnackbarMessage('File restored successfully');
              setSnackbarVisible(true);
              await loadQuarantineData();
            } else {
              Alert.alert('Restore Failed', result.error || 'Failed to restore file');
            }
          },
        },
      ]
    );
  };

  const handleDelete = async (fileId: string, fileName: string) => {
    Alert.alert(
      'Delete File',
      `Permanently delete "${fileName}"? This cannot be undone.`,
      [
        {text: 'Cancel', style: 'cancel'},
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            const result = await ApiService.request(`/quarantine/${fileId}`, {
              method: 'DELETE',
            });
            if (result.success) {
              setSnackbarMessage('File deleted permanently');
              setSnackbarVisible(true);
              await loadQuarantineData();
            } else {
              Alert.alert('Delete Failed', result.error || 'Failed to delete file');
            }
          },
        },
      ]
    );
  };

  const handleClearAll = () => {
    Alert.alert(
      'Clear All Quarantine',
      'Permanently delete all quarantined files? This cannot be undone.',
      [
        {text: 'Cancel', style: 'cancel'},
        {
          text: 'Delete All',
          style: 'destructive',
          onPress: async () => {
            // Delete each file
            for (const file of files) {
              await ApiService.request(`/quarantine/${file.id}`, {
                method: 'DELETE',
              });
            }
            setSnackbarMessage('All files deleted');
            setSnackbarVisible(true);
            await loadQuarantineData();
          },
        },
      ]
    );
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const getThreatIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'virus':
        return 'virus';
      case 'trojan':
        return 'bug';
      case 'malware':
        return 'biohazard';
      case 'ransomware':
        return 'lock-alert';
      case 'spyware':
        return 'eye';
      default:
        return 'alert-circle';
    }
  };

  const renderFile = ({item}: {item: QuarantinedFile}) => (
    <Card style={styles.fileCard}>
      <Card.Content>
        <View style={styles.fileHeader}>
          <Icon name={getThreatIcon(item.threatType)} size={32} color="#f44336" />
          <View style={styles.fileInfo}>
            <Text style={styles.fileName} numberOfLines={1}>
              {item.fileName}
            </Text>
            <Text style={styles.filePath} numberOfLines={1}>
              {item.originalPath}
            </Text>
            <View style={styles.fileMeta}>
              <Chip icon="calendar" mode="flat" compact style={styles.chip}>
                {new Date(item.dateQuarantined).toLocaleDateString()}
              </Chip>
              <Chip icon="file" mode="flat" compact style={styles.chip}>
                {formatFileSize(item.fileSize)}
              </Chip>
            </View>
          </View>
        </View>

        <View style={styles.threatInfo}>
          <Chip
            icon="alert"
            mode="flat"
            textStyle={{color: '#f44336'}}
            style={[styles.threatChip, {backgroundColor: '#ffebee'}]}>
            {item.threatName}
          </Chip>
          <Chip
            icon="biohazard"
            mode="flat"
            textStyle={{color: '#ff9800'}}
            style={[styles.threatChip, {backgroundColor: '#fff3e0'}]}>
            {item.threatType}
          </Chip>
        </View>

        <View style={styles.actions}>
          <Button
            mode="outlined"
            icon="restore"
            onPress={() => handleRestore(item.id, item.fileName)}
            style={styles.actionButton}>
            Restore
          </Button>
          <Button
            mode="contained"
            icon="delete"
            buttonColor="#f44336"
            onPress={() => handleDelete(item.id, item.fileName)}
            style={styles.actionButton}>
            Delete
          </Button>
        </View>
      </Card.Content>
    </Card>
  );

  return (
    <View style={[styles.container, {backgroundColor: theme.colors.background}]}>
      <Surface style={styles.statsCard} elevation={2}>
        <View style={styles.statsRow}>
          <View style={styles.stat}>
            <Icon name="file-lock" size={32} color="#f44336" />
            <Text style={styles.statValue}>{stats.totalFiles}</Text>
            <Text style={styles.statLabel}>Quarantined Files</Text>
          </View>
          <View style={styles.statDivider} />
          <View style={styles.stat}>
            <Icon name="harddisk" size={32} color="#ff9800" />
            <Text style={styles.statValue}>{formatFileSize(stats.totalSize)}</Text>
            <Text style={styles.statLabel}>Total Size</Text>
          </View>
        </View>
      </Surface>

      {files.length === 0 ? (
        <View style={styles.emptyState}>
          <Icon name="shield-check" size={80} color="#4caf50" />
          <Text style={styles.emptyTitle}>No Quarantined Files</Text>
          <Text style={styles.emptySubtitle}>
            All detected threats will appear here
          </Text>
        </View>
      ) : (
        <>
          <FlatList
            data={files}
            renderItem={renderFile}
            keyExtractor={(item) => item.id}
            refreshControl={
              <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
            }
            contentContainerStyle={styles.listContent}
          />
          <View style={styles.footer}>
            <Button
              mode="contained"
              icon="delete-sweep"
              buttonColor="#f44336"
              onPress={handleClearAll}
              style={styles.clearButton}>
              Clear All
            </Button>
          </View>
        </>
      )}

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
  statsCard: {
    margin: 16,
    padding: 16,
    borderRadius: 12,
  },
  statsRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
  },
  stat: {
    flex: 1,
    alignItems: 'center',
    gap: 8,
  },
  statDivider: {
    width: 1,
    backgroundColor: '#e0e0e0',
    marginHorizontal: 16,
  },
  statValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
  },
  statLabel: {
    fontSize: 12,
    color: '#666',
    textAlign: 'center',
  },
  listContent: {
    padding: 16,
    paddingTop: 0,
    paddingBottom: 100,
  },
  fileCard: {
    marginBottom: 16,
  },
  fileHeader: {
    flexDirection: 'row',
    gap: 12,
    marginBottom: 12,
  },
  fileInfo: {
    flex: 1,
  },
  fileName: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#333',
  },
  filePath: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  fileMeta: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 8,
  },
  chip: {
    height: 28,
  },
  threatInfo: {
    flexDirection: 'row',
    gap: 8,
    marginBottom: 12,
    flexWrap: 'wrap',
  },
  threatChip: {
    height: 32,
  },
  actions: {
    flexDirection: 'row',
    gap: 12,
    marginTop: 8,
  },
  actionButton: {
    flex: 1,
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
  footer: {
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    padding: 16,
    backgroundColor: '#fff',
    borderTopWidth: 1,
    borderTopColor: '#e0e0e0',
  },
  clearButton: {
    paddingVertical: 4,
  },
});

export default QuarantineScreen;
