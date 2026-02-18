import React, {useEffect, useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  Alert,
} from 'react-native';
import {Card, Button, ProgressBar, Chip, Surface, Snackbar, useTheme} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import ApiService from '../services/ApiService';

interface CleanupCategory {
  name: string;
  displayName: string;
  description: string;
  fileCount: number;
  totalSize: number;
  icon: string;
  color: string;
}

const DiskCleanupScreen = (): JSX.Element => {
  const theme = useTheme();
  const [refreshing, setRefreshing] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [cleaning, setCleaning] = useState<string | null>(null);
  const [categories, setCategories] = useState<CleanupCategory[]>([]);
  const [totalSpace, setTotalSpace] = useState(0);
  const [snackbarVisible, setSnackbarVisible] = useState(false);
  const [snackbarMessage, setSnackbarMessage] = useState('');

  useEffect(() => {
    loadCleanupData();
  }, []);

  const loadCleanupData = async () => {
    const result = await ApiService.request('/disk/results');
    if (result.success && result.data) {
      const categoriesData: CleanupCategory[] = [
        {
          name: 'tempFiles',
          displayName: 'Temporary Files',
          description: 'System and user temp files',
          fileCount: result.data.tempFiles?.fileCount || 0,
          totalSize: result.data.tempFiles?.totalSize || 0,
          icon: 'file-clock',
          color: '#2196f3',
        },
        {
          name: 'browserCache',
          displayName: 'Browser Cache',
          description: 'Chrome, Edge, Firefox cache',
          fileCount: result.data.browserCache?.fileCount || 0,
          totalSize: result.data.browserCache?.totalSize || 0,
          icon: 'web',
          color: '#ff9800',
        },
        {
          name: 'windowsUpdate',
          displayName: 'Windows Update Files',
          description: 'Old update installation files',
          fileCount: result.data.windowsUpdate?.fileCount || 0,
          totalSize: result.data.windowsUpdate?.totalSize || 0,
          icon: 'microsoft-windows',
          color: '#00bcd4',
        },
        {
          name: 'recycleBin',
          displayName: 'Recycle Bin',
          description: 'Deleted files in recycle bin',
          fileCount: result.data.recycleBin?.fileCount || 0,
          totalSize: result.data.recycleBin?.totalSize || 0,
          icon: 'delete',
          color: '#9c27b0',
        },
        {
          name: 'downloads',
          displayName: 'Old Downloads',
          description: 'Downloads older than 30 days',
          fileCount: result.data.downloads?.fileCount || 0,
          totalSize: result.data.downloads?.totalSize || 0,
          icon: 'download',
          color: '#4caf50',
        },
      ];

      setCategories(categoriesData);
      
      // Calculate total
      const total = categoriesData.reduce((sum, cat) => sum + cat.totalSize, 0);
      setTotalSpace(total);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadCleanupData();
    setRefreshing(false);
  };

  const handleAnalyze = async () => {
    setAnalyzing(true);
    const result = await ApiService.request('/disk/analyze', {
      method: 'GET',
    });
    setAnalyzing(false);

    if (result.success) {
      await loadCleanupData();
      setSnackbarMessage('Analysis complete');
      setSnackbarVisible(true);
    } else {
      Alert.alert('Analysis Failed', result.error || 'Failed to analyze disk');
    }
  };

  const handleCleanCategory = async (categoryName: string, displayName: string) => {
    Alert.alert(
      'Clean Files',
      `Delete all files in "${displayName}"? This cannot be undone.`,
      [
        {text: 'Cancel', style: 'cancel'},
        {
          text: 'Clean',
          style: 'destructive',
          onPress: async () => {
            setCleaning(categoryName);
            const result = await ApiService.request(`/disk/clean/${categoryName}`, {
              method: 'POST',
            });
            setCleaning(null);

            if (result.success) {
              setSnackbarMessage(`${displayName} cleaned successfully`);
              setSnackbarVisible(true);
              await loadCleanupData();
            } else {
              Alert.alert('Clean Failed', result.error || 'Failed to clean files');
            }
          },
        },
      ]
    );
  };

  const handleCleanAll = () => {
    Alert.alert(
      'Clean All',
      `Delete all junk files (${formatSize(totalSpace)})? This cannot be undone.`,
      [
        {text: 'Cancel', style: 'cancel'},
        {
          text: 'Clean All',
          style: 'destructive',
          onPress: async () => {
            setCleaning('all');
            const result = await ApiService.request('/disk/clean/all', {
              method: 'POST',
            });
            setCleaning(null);

            if (result.success) {
              setSnackbarMessage('All files cleaned successfully');
              setSnackbarVisible(true);
              await loadCleanupData();
            } else {
              Alert.alert('Clean Failed', result.error || 'Failed to clean files');
            }
          },
        },
      ]
    );
  };

  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const renderCategory = (category: CleanupCategory) => (
    <Card key={category.name} style={styles.categoryCard}>
      <Card.Content>
        <View style={styles.categoryHeader}>
          <View style={[styles.iconContainer, {backgroundColor: `${category.color}20`}]}>
            <Icon name={category.icon} size={32} color={category.color} />
          </View>
          <View style={styles.categoryInfo}>
            <Text style={styles.categoryName}>{category.displayName}</Text>
            <Text style={styles.categoryDescription}>{category.description}</Text>
          </View>
        </View>

        <View style={styles.categoryStats}>
          <View style={styles.statItem}>
            <Icon name="file-multiple" size={20} color="#666" />
            <Text style={styles.statText}>
              {category.fileCount.toLocaleString()} files
            </Text>
          </View>
          <View style={styles.statItem}>
            <Icon name="harddisk" size={20} color="#666" />
            <Text style={styles.statText}>{formatSize(category.totalSize)}</Text>
          </View>
        </View>

        {category.totalSize > 0 && (
          <Button
            mode="contained"
            icon="broom"
            buttonColor={category.color}
            onPress={() => handleCleanCategory(category.name, category.displayName)}
            loading={cleaning === category.name}
            disabled={cleaning !== null}
            style={styles.cleanButton}>
            Clean
          </Button>
        )}
      </Card.Content>
    </Card>
  );

  return (
    <View style={[styles.container, {backgroundColor: theme.colors.background}]}>
      <Surface style={styles.summaryCard} elevation={2}>
        <View style={styles.summaryContent}>
          <Icon name="harddisk-remove" size={48} color="#f44336" />
          <View style={styles.summaryInfo}>
            <Text style={styles.summaryValue}>{formatSize(totalSpace)}</Text>
            <Text style={styles.summaryLabel}>Space can be freed</Text>
          </View>
          <Button
            mode="contained"
            icon="magnify-scan"
            onPress={handleAnalyze}
            loading={analyzing}
            disabled={analyzing}
            style={styles.analyzeButton}>
            Analyze
          </Button>
        </View>
      </Surface>

      <ScrollView
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
        }
        contentContainerStyle={styles.scrollContent}>
        
        {categories.map(renderCategory)}

        {totalSpace > 0 && (
          <Button
            mode="contained"
            icon="delete-sweep"
            buttonColor="#f44336"
            onPress={handleCleanAll}
            loading={cleaning === 'all'}
            disabled={cleaning !== null}
            style={styles.cleanAllButton}>
            Clean All ({formatSize(totalSpace)})
          </Button>
        )}

        <Card style={styles.infoCard}>
          <Card.Content>
            <View style={styles.infoRow}>
              <Icon name="information" size={24} color="#2196f3" />
              <Text style={styles.infoText}>
                Disk cleanup safely removes temporary and unnecessary files to free up space.
                Your personal files and documents are never touched.
              </Text>
            </View>
          </Card.Content>
        </Card>
      </ScrollView>

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
  summaryCard: {
    margin: 16,
    padding: 16,
    borderRadius: 12,
  },
  summaryContent: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 16,
  },
  summaryInfo: {
    flex: 1,
  },
  summaryValue: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#f44336',
  },
  summaryLabel: {
    fontSize: 14,
    color: '#666',
    marginTop: 4,
  },
  analyzeButton: {
    paddingHorizontal: 8,
  },
  scrollContent: {
    padding: 16,
    paddingTop: 0,
  },
  categoryCard: {
    marginBottom: 16,
  },
  categoryHeader: {
    flexDirection: 'row',
    gap: 12,
    marginBottom: 12,
  },
  iconContainer: {
    width: 56,
    height: 56,
    borderRadius: 28,
    justifyContent: 'center',
    alignItems: 'center',
  },
  categoryInfo: {
    flex: 1,
    justifyContent: 'center',
  },
  categoryName: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#333',
  },
  categoryDescription: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  categoryStats: {
    flexDirection: 'row',
    gap: 24,
    marginBottom: 12,
  },
  statItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  statText: {
    fontSize: 14,
    color: '#666',
  },
  cleanButton: {
    marginTop: 8,
  },
  cleanAllButton: {
    marginVertical: 16,
    paddingVertical: 4,
  },
  infoCard: {
    marginBottom: 16,
    backgroundColor: '#e3f2fd',
  },
  infoRow: {
    flexDirection: 'row',
    gap: 12,
    alignItems: 'flex-start',
  },
  infoText: {
    flex: 1,
    fontSize: 14,
    color: '#666',
    lineHeight: 20,
  },
});

export default DiskCleanupScreen;
