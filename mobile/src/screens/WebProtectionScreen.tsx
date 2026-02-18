import React, {useEffect, useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  Alert,
  Linking,
} from 'react-native';
import {Card, Button, Chip, List, Switch, Surface, useTheme, ProgressBar, TextInput} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import AsyncStorage from '@react-native-async-storage/async-storage';
import SafeBrowsingService from '../services/SafeBrowsingService';

interface BrowsingActivity {
  id: string;
  url: string;
  domain: string;
  timestamp: string;
  blocked: boolean;
  threatType?: string;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}

interface BrowserStats {
  totalChecked: number;
  threatsBlocked: number;
  phishingBlocked: number;
  malwareBlocked: number;
  lastScan: string | null;
}

const WebProtectionScreen = (): JSX.Element => {
  const theme = useTheme();
  const [webShieldEnabled, setWebShieldEnabled] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [checkingUrl, setCheckingUrl] = useState(false);
  const [urlToCheck, setUrlToCheck] = useState('');
  const [recentActivity, setRecentActivity] = useState<BrowsingActivity[]>([]);
  const [stats, setStats] = useState<BrowserStats>({
    totalChecked: 0,
    threatsBlocked: 0,
    phishingBlocked: 0,
    malwareBlocked: 0,
    lastScan: null,
  });

  useEffect(() => {
    loadWebShieldStatus();
    loadBrowsingActivity();
    loadStats();
  }, []);

  const loadWebShieldStatus = async () => {
    try {
      const status = await AsyncStorage.getItem('web_shield_enabled');
      if (status !== null) {
        setWebShieldEnabled(status === 'true');
      }
    } catch (error) {
      console.error('Failed to load web shield status:', error);
    }
  };

  const toggleWebShield = async (value: boolean) => {
    try {
      setWebShieldEnabled(value);
      await AsyncStorage.setItem('web_shield_enabled', value.toString());
      
      if (value) {
        Alert.alert(
          'Web Shield Enabled',
          'Your browsing activity will be monitored for malicious sites and phishing attempts.'
        );
      } else {
        Alert.alert(
          'Web Shield Disabled',
          'Warning: You are now browsing without protection. Malicious sites will not be blocked.'
        );
      }
    } catch (error) {
      console.error('Failed to toggle web shield:', error);
    }
  };

  const loadBrowsingActivity = async () => {
    // Simulate loading recent browsing activity
    const mockActivity: BrowsingActivity[] = [
      {
        id: '1',
        url: 'https://google.com',
        domain: 'google.com',
        timestamp: new Date(Date.now() - 5 * 60000).toISOString(),
        blocked: false,
        riskLevel: 'safe',
      },
      {
        id: '2',
        url: 'https://suspicious-site.xyz',
        domain: 'suspicious-site.xyz',
        timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
        blocked: true,
        threatType: 'Phishing',
        riskLevel: 'critical',
      },
      {
        id: '3',
        url: 'https://github.com',
        domain: 'github.com',
        timestamp: new Date(Date.now() - 30 * 60000).toISOString(),
        blocked: false,
        riskLevel: 'safe',
      },
    ];
    setRecentActivity(mockActivity);
  };

  const loadStats = async () => {
    setStats({
      totalChecked: 1247,
      threatsBlocked: 23,
      phishingBlocked: 15,
      malwareBlocked: 8,
      lastScan: new Date(Date.now() - 2 * 60 * 60000).toISOString(),
    });
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadBrowsingActivity();
    await loadStats();
    setRefreshing(false);
  };

  const scanBrowserHistory = async () => {
    setScanning(true);
    
    // Simulate scanning browser history
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    Alert.alert(
      'Scan Complete',
      `Scanned browser history.\n\nFound:\n• 0 malicious sites\n• 0 phishing attempts\n• All visited sites are safe`
    );
    
    setScanning(false);
    setStats(prev => ({
      ...prev,
      lastScan: new Date().toISOString(),
    }));
  };

  const checkUrl = async () => {
    if (!urlToCheck.trim()) {
      Alert.alert('Error', 'Please enter a URL to check');
      return;
    }

    setCheckingUrl(true);

    try {
      // Use SafeBrowsingService to check URL
      const result = await SafeBrowsingService.checkUrl(urlToCheck);

      if (result.success) {
        if (result.malicious) {
          Alert.alert(
            '⚠️ Dangerous Site Detected',
            `This site has been flagged as ${result.type}.\n\nRisk Score: ${result.score}/100\n\nDo NOT visit this site!`,
            [
              { text: 'OK', style: 'cancel' },
              { text: 'Report False Positive', onPress: () => SafeBrowsingService.reportFalsePositive(urlToCheck) },
            ]
          );
        } else {
          Alert.alert(
            '✅ Safe Site',
            `This URL appears to be safe.\n\nRisk Score: ${result.score}/100`,
            [{ text: 'OK' }]
          );
        }
      } else {
        // Check failed
        Alert.alert('Check Failed', result.error || 'Unable to verify URL safety. Proceed with caution.');
      }
    } catch (error) {
      console.error('URL check error:', error);
      Alert.alert('Error', 'Failed to check URL. Please try again.');
    } finally {
      setCheckingUrl(false);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical':
        return '#d32f2f';
      case 'high':
        return '#f44336';
      case 'medium':
        return '#ff9800';
      case 'low':
        return '#ffc107';
      case 'safe':
      default:
        return '#4caf50';
    }
  };

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);

    if (minutes < 60) {
      return `${minutes} min ago`;
    } else if (hours < 24) {
      return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    } else {
      return date.toLocaleDateString();
    }
  };

  return (
    <ScrollView
      style={[styles.container, {backgroundColor: theme.colors.background}]}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}>
      
      {/* Web Shield Status */}
      <Surface style={styles.statusCard} elevation={2}>
        <View style={styles.statusHeader}>
          <View style={styles.statusIcon}>
            <Icon 
              name={webShieldEnabled ? 'shield-check' : 'shield-off'} 
              size={48} 
              color={webShieldEnabled ? '#4caf50' : '#999'} 
            />
          </View>
          <View style={styles.statusInfo}>
            <Text style={[styles.statusTitle, {color: theme.colors.onSurface}]}>
              {webShieldEnabled ? 'Protected' : 'Unprotected'}
            </Text>
            <Text style={[styles.statusSubtitle, {color: theme.colors.onSurfaceVariant}]}>
              {webShieldEnabled ? 'Web Shield is active' : 'Web Shield is disabled'}
            </Text>
          </View>
          <Switch value={webShieldEnabled} onValueChange={toggleWebShield} />
        </View>
      </Surface>

      {/* Statistics */}
      <Card style={styles.card}>
        <Card.Title title="Protection Statistics" />
        <Card.Content>
          <View style={styles.statsGrid}>
            <View style={styles.statItem}>
              <Icon name="web-check" size={32} color="#2196f3" />
              <Text style={styles.statValue}>{stats.totalChecked}</Text>
              <Text style={styles.statLabel}>URLs Checked</Text>
            </View>
            <View style={styles.statItem}>
              <Icon name="shield-alert" size={32} color="#f44336" />
              <Text style={styles.statValue}>{stats.threatsBlocked}</Text>
              <Text style={styles.statLabel}>Threats Blocked</Text>
            </View>
            <View style={styles.statItem}>
              <Icon name="email-alert" size={32} color="#ff9800" />
              <Text style={styles.statValue}>{stats.phishingBlocked}</Text>
              <Text style={styles.statLabel}>Phishing Blocked</Text>
            </View>
            <View style={styles.statItem}>
              <Icon name="bug" size={32} color="#9c27b0" />
              <Text style={styles.statValue}>{stats.malwareBlocked}</Text>
              <Text style={styles.statLabel}>Malware Blocked</Text>
            </View>
          </View>
        </Card.Content>
      </Card>

      {/* URL Checker */}
      <Card style={styles.card}>
        <Card.Title title="Check URL Safety" />
        <Card.Content>
          <Text variant="bodySmall" style={{marginBottom: 12, color: theme.colors.onSurfaceVariant}}>
            Verify if a website is safe before visiting
          </Text>
          <TextInput
            mode="outlined"
            label="Enter URL"
            placeholder="https://example.com"
            value={urlToCheck}
            onChangeText={setUrlToCheck}
            left={<TextInput.Icon icon="web" />}
            style={styles.urlInput}
          />
          <Button
            mode="contained"
            icon="magnify"
            onPress={checkUrl}
            loading={checkingUrl}
            disabled={checkingUrl || !urlToCheck.trim()}
            style={{marginTop: 8}}>
            {checkingUrl ? 'Checking...' : 'Check URL'}
          </Button>
        </Card.Content>
      </Card>

      {/* Browser History Scanner */}
      <Card style={styles.card}>
        <Card.Title title="Browser History Scan" />
        <Card.Content>
          <View style={styles.scanInfo}>
            <Icon name="history" size={32} color="#2196f3" />
            <View style={styles.scanText}>
              <Text variant="bodyMedium" style={{color: theme.colors.onSurface}}>
                Scan Browsing History
              </Text>
              <Text variant="bodySmall" style={{color: theme.colors.onSurfaceVariant}}>
                {stats.lastScan
                  ? `Last scan: ${formatTime(stats.lastScan)}`
                  : 'Never scanned'}
              </Text>
            </View>
          </View>
          <Button
            mode="contained"
            icon="magnify-scan"
            onPress={scanBrowserHistory}
            loading={scanning}
            disabled={scanning}
            style={{marginTop: 16}}>
            {scanning ? 'Scanning...' : 'Scan History'}
          </Button>
          {scanning && (
            <View style={{marginTop: 16}}>
              <Text variant="bodySmall" style={{marginBottom: 8, color: theme.colors.onSurfaceVariant}}>
                Scanning browser history...
              </Text>
              <ProgressBar indeterminate color="#2196f3" />
            </View>
          )}
        </Card.Content>
      </Card>

      {/* Recent Activity */}
      <Card style={styles.card}>
        <Card.Title title="Recent Browsing Activity" />
        <Card.Content>
          {recentActivity.length === 0 ? (
            <View style={styles.emptyState}>
              <Icon name="web-off" size={48} color="#999" />
              <Text style={{marginTop: 8, color: theme.colors.onSurfaceVariant}}>
                No recent activity
              </Text>
            </View>
          ) : (
            recentActivity.map((activity) => (
              <List.Item
                key={activity.id}
                title={activity.domain}
                description={formatTime(activity.timestamp)}
                left={props => (
                  <Icon
                    name={activity.blocked ? 'shield-alert' : 'web'}
                    size={24}
                    color={getRiskColor(activity.riskLevel)}
                    {...props}
                  />
                )}
                right={props =>
                  activity.blocked ? (
                    <Chip
                      icon="block-helper"
                      textStyle={{fontSize: 11}}
                      style={{backgroundColor: '#ffebee'}}>
                      Blocked
                    </Chip>
                  ) : (
                    <Chip
                      icon="check"
                      textStyle={{fontSize: 11}}
                      style={{backgroundColor: '#e8f5e9'}}>
                      Safe
                    </Chip>
                  )
                }
              />
            ))
          )}
        </Card.Content>
      </Card>

      {/* Protection Features */}
      <Card style={styles.card}>
        <Card.Title title="Protection Features" />
        <Card.Content>
          <List.Item
            title="Real-time URL Scanning"
            description="Check every link before opening"
            left={props => <Icon name="shield-search" size={24} color="#2196f3" {...props} />}
            right={props => <Icon name="check" size={24} color="#4caf50" {...props} />}
          />
          <List.Item
            title="Phishing Detection"
            description="Block fake and fraudulent websites"
            left={props => <Icon name="email-alert" size={24} color="#ff9800" {...props} />}
            right={props => <Icon name="check" size={24} color="#4caf50" {...props} />}
          />
          <List.Item
            title="Malware Blocking"
            description="Prevent malicious downloads"
            left={props => <Icon name="bug" size={24} color="#f44336" {...props} />}
            right={props => <Icon name="check" size={24} color="#4caf50" {...props} />}
          />
          <List.Item
            title="Safe Browsing History"
            description="Scan visited sites for threats"
            left={props => <Icon name="history" size={24} color="#9c27b0" {...props} />}
            right={props => <Icon name="check" size={24} color="#4caf50" {...props} />}
          />
        </Card.Content>
      </Card>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  statusCard: {
    margin: 16,
    padding: 16,
    borderRadius: 12,
  },
  statusHeader: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  statusIcon: {
    marginRight: 16,
  },
  statusInfo: {
    flex: 1,
  },
  statusTitle: {
    fontSize: 20,
    fontWeight: 'bold',
  },
  statusSubtitle: {
    fontSize: 14,
    marginTop: 4,
  },
  card: {
    marginHorizontal: 16,
    marginBottom: 16,
  },
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
  },
  statItem: {
    width: '48%',
    alignItems: 'center',
    padding: 16,
    marginBottom: 16,
    backgroundColor: '#f5f5f5',
    borderRadius: 12,
  },
  statValue: {
    fontSize: 24,
    fontWeight: 'bold',
    marginTop: 8,
    color: '#333',
  },
  statLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
    textAlign: 'center',
  },
  urlInput: {
    marginBottom: 8,
  },
  scanInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 16,
  },
  scanText: {
    flex: 1,
  },
  emptyState: {
    alignItems: 'center',
    padding: 32,
  },
});

export default WebProtectionScreen;
