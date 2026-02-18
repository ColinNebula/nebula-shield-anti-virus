/**
 * Network Traffic Monitor Screen
 * Real-time network monitoring with app firewall, tracker blocking, and threat detection
 */

import React, { useState, useEffect } from 'react';
import {
  View,
  ScrollView,
  StyleSheet,
  RefreshControl,
  TouchableOpacity,
  Alert,
} from 'react-native';
import {
  Text,
  Card,
  Button,
  SegmentedButtons,
  Chip,
  Divider,
  IconButton,
  Switch,
  ActivityIndicator,
  Badge,
  Dialog,
  Portal,
  TextInput,
  RadioButton,
} from 'react-native-paper';
import { MaterialCommunityIcons } from '@expo/vector-icons';
import {
  NetworkTrafficService,
  NetworkConnection,
  TrafficStats,
  SuspiciousActivity,
  AppTrafficData,
  FirewallRule,
  BlockedTracker,
  SuspiciousServer,
} from '../services/NetworkTrafficService';

export default function NetworkTrafficScreen() {
  const [activeTab, setActiveTab] = useState('monitor');
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  // Monitor tab state
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [monitoring, setMonitoring] = useState(false);

  // Apps tab state
  const [appTraffic, setAppTraffic] = useState<AppTrafficData[]>([]);

  // Firewall tab state
  const [firewallRules, setFirewallRules] = useState<FirewallRule[]>([]);
  const [showFirewallDialog, setShowFirewallDialog] = useState(false);
  const [newRule, setNewRule] = useState({
    appName: '',
    packageName: '',
    ruleType: 'block_all' as FirewallRule['type'],
  });

  // Trackers tab state
  const [blockedTrackers, setBlockedTrackers] = useState<BlockedTracker[]>([]);

  // Threats tab state
  const [suspiciousActivities, setSuspiciousActivities] = useState<SuspiciousActivity[]>([]);
  const [suspiciousServers, setSuspiciousServers] = useState<SuspiciousServer[]>([]);

  useEffect(() => {
    loadData();
  }, [activeTab]);

  const loadData = async () => {
    setLoading(true);
    try {
      if (activeTab === 'monitor') {
        await loadMonitorData();
      } else if (activeTab === 'apps') {
        await loadAppData();
      } else if (activeTab === 'firewall') {
        await loadFirewallData();
      } else if (activeTab === 'trackers') {
        await loadTrackerData();
      } else if (activeTab === 'threats') {
        await loadThreatData();
      }
    } catch (error) {
      console.error('Load data error:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadMonitorData = async () => {
    const [connectionsData, statsData] = await Promise.all([
      NetworkTrafficService.getActiveConnections(),
      NetworkTrafficService.getTrafficStats(),
    ]);
    setConnections(connectionsData);
    setStats(statsData);
  };

  const loadAppData = async () => {
    const data = await NetworkTrafficService.getAppTrafficData();
    setAppTraffic(data);
  };

  const loadFirewallData = async () => {
    const rules = await NetworkTrafficService.getFirewallRules();
    setFirewallRules(rules);
  };

  const loadTrackerData = async () => {
    const trackers = await NetworkTrafficService.getBlockedTrackers();
    setBlockedTrackers(trackers);
  };

  const loadThreatData = async () => {
    const [activities, servers] = await Promise.all([
      NetworkTrafficService.getSuspiciousActivities(),
      NetworkTrafficService.getSuspiciousServers(),
    ]);
    setSuspiciousActivities(activities);
    setSuspiciousServers(servers);
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  };

  const handleStartMonitoring = () => {
    setMonitoring(true);
    NetworkTrafficService.startMonitoring((data) => {
      setConnections(data.connections);
      setStats(data.stats);
    });
  };

  const handleStopMonitoring = () => {
    setMonitoring(false);
    NetworkTrafficService.stopMonitoring();
  };

  const handleBlockConnection = async (connection: NetworkConnection) => {
    Alert.alert(
      'Block Connection',
      `Block connection to ${connection.remoteHost}?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Block',
          style: 'destructive',
          onPress: async () => {
            const success = await NetworkTrafficService.blockConnection(connection.id);
            if (success) {
              await loadMonitorData();
            }
          },
        },
      ]
    );
  };

  const handleToggleAppBlock = async (app: AppTrafficData) => {
    if (app.isBlocked) {
      await NetworkTrafficService.unblockApp(app.app);
    } else {
      await NetworkTrafficService.blockApp(app.app);
    }
    await loadAppData();
  };

  const handleAddFirewallRule = () => {
    setShowFirewallDialog(true);
  };

  const handleSaveFirewallRule = async () => {
    if (!newRule.appName || !newRule.packageName) {
      Alert.alert('Error', 'Please fill in all fields');
      return;
    }

    try {
      const success = await NetworkTrafficService.addFirewallRule(
        newRule.appName,
        newRule.packageName,
        newRule.ruleType
      );

      if (success) {
        Alert.alert('Success', 'Firewall rule added successfully');
        setShowFirewallDialog(false);
        setNewRule({ appName: '', packageName: '', ruleType: 'block_all' });
        await loadFirewallData();
      } else {
        Alert.alert('Error', 'Failed to add firewall rule');
      }
    } catch (error) {
      Alert.alert('Error', 'An error occurred while adding the rule');
    }
  };

  const handleDeleteFirewallRule = async (ruleId: string) => {
    Alert.alert(
      'Delete Rule',
      'Are you sure you want to delete this firewall rule?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            const success = await NetworkTrafficService.removeFirewallRule(ruleId);
            if (success) {
              await loadFirewallData();
            }
          },
        },
      ]
    );
  };

  const handleBlockServer = async (server: SuspiciousServer) => {
    Alert.alert(
      'Block Server',
      `Block all connections to ${server.domain} (${server.ip})?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Block',
          style: 'destructive',
          onPress: async () => {
            await NetworkTrafficService.blockServer(server.ip);
            await loadThreatData();
          },
        },
      ]
    );
  };

  const renderMonitorTab = () => (
    <ScrollView
      style={styles.tabContent}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={handleRefresh} />
      }
    >
      {/* Monitoring Control */}
      <Card style={styles.card}>
        <Card.Content>
          <View style={styles.monitoringControl}>
            <View style={styles.monitoringInfo}>
              <MaterialCommunityIcons
                name={monitoring ? 'wifi' : 'wifi-off' as any}
                size={32}
                color={monitoring ? '#4caf50' : '#666'}
              />
              <View style={styles.monitoringText}>
                <Text style={styles.monitoringTitle}>
                  Real-time Monitoring
                </Text>
                <Text style={styles.monitoringStatus}>
                  {monitoring ? 'Active - Updating every 3s' : 'Inactive'}
                </Text>
              </View>
            </View>
            <Button
              mode={monitoring ? 'outlined' : 'contained'}
              onPress={monitoring ? handleStopMonitoring : handleStartMonitoring}
            >
              {monitoring ? 'Stop' : 'Start'}
            </Button>
          </View>
        </Card.Content>
      </Card>

      {/* Statistics */}
      {stats && (
        <Card style={styles.card}>
          <Card.Title title="Traffic Statistics" />
          <Card.Content>
            <View style={styles.statsGrid}>
              <View style={styles.statItem}>
                <MaterialCommunityIcons name="connection" size={24} color="#2196f3" />
                <Text style={styles.statValue}>{stats.activeConnections}</Text>
                <Text style={styles.statLabel}>Active</Text>
              </View>
              <View style={styles.statItem}>
                <MaterialCommunityIcons name="alert" size={24} color="#ff9800" />
                <Text style={styles.statValue}>{stats.suspiciousConnections}</Text>
                <Text style={styles.statLabel}>Suspicious</Text>
              </View>
              <View style={styles.statItem}>
                <MaterialCommunityIcons name="shield-check" size={24} color="#4caf50" />
                <Text style={styles.statValue}>{stats.blockedConnections}</Text>
                <Text style={styles.statLabel}>Blocked</Text>
              </View>
            </View>

            <Divider style={styles.divider} />

            <View style={styles.dataUsage}>
              <View style={styles.dataItem}>
                <MaterialCommunityIcons name="download" size={20} color="#4caf50" />
                <Text style={styles.dataLabel}>Downloaded:</Text>
                <Text style={styles.dataValue}>
                  {NetworkTrafficService.formatBytes(stats.totalBytesIn)}
                </Text>
              </View>
              <View style={styles.dataItem}>
                <MaterialCommunityIcons name="upload" size={20} color="#2196f3" />
                <Text style={styles.dataLabel}>Uploaded:</Text>
                <Text style={styles.dataValue}>
                  {NetworkTrafficService.formatBytes(stats.totalBytesOut)}
                </Text>
              </View>
            </View>
          </Card.Content>
        </Card>
      )}

      {/* Active Connections */}
      <Card style={styles.card}>
        <Card.Title 
          title="Active Connections" 
          right={(props) => (
            <Badge size={24} style={styles.badge}>
              {connections.length}
            </Badge>
          )}
        />
        <Card.Content>
          {connections.map((conn, index) => (
            <View key={conn.id}>
              {index > 0 && <Divider style={styles.connectionDivider} />}
              <View style={styles.connectionItem}>
                <View style={styles.connectionHeader}>
                  <MaterialCommunityIcons name={conn.appIcon as any} size={24} color="#666" />
                  <Text style={styles.connectionApp}>{conn.app}</Text>
                  <Chip
                    mode="flat"
                    style={[
                      styles.threatChip,
                      { backgroundColor: NetworkTrafficService.getThreatColor(conn.threatLevel) },
                    ]}
                    textStyle={styles.threatChipText}
                  >
                    {conn.threatLevel.toUpperCase()}
                  </Chip>
                </View>

                <View style={styles.connectionDetails}>
                  <Text style={styles.connectionText}>
                    <MaterialCommunityIcons name="web" size={12} /> {conn.protocol} → {conn.remoteHost}
                  </Text>
                  <Text style={styles.connectionText}>
                    <MaterialCommunityIcons name="map-marker" size={12} /> {conn.remoteAddress} ({conn.country})
                  </Text>
                  <View style={styles.connectionStats}>
                    <Text style={styles.connectionText}>
                      ↓ {NetworkTrafficService.formatBytes(conn.bytesIn)}
                    </Text>
                    <Text style={styles.connectionText}>
                      ↑ {NetworkTrafficService.formatBytes(conn.bytesOut)}
                    </Text>
                    <Text style={styles.connectionText}>
                      ⏱ {NetworkTrafficService.formatDuration(conn.duration)}
                    </Text>
                  </View>

                  {conn.isSuspicious && (
                    <View style={styles.suspiciousRow}>
                      <MaterialCommunityIcons name="alert" size={16} color="#f44336" />
                      <Text style={styles.suspiciousText}>{conn.reason}</Text>
                      <IconButton
                        icon="block-helper"
                        size={20}
                        iconColor="#f44336"
                        onPress={() => handleBlockConnection(conn)}
                      />
                    </View>
                  )}
                </View>
              </View>
            </View>
          ))}
        </Card.Content>
      </Card>
    </ScrollView>
  );

  const renderAppsTab = () => (
    <ScrollView
      style={styles.tabContent}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={handleRefresh} />
      }
    >
      <Card style={styles.card}>
        <Card.Title title="App Data Usage" />
        <Card.Content>
          {appTraffic.map((app, index) => (
            <View key={app.packageName}>
              {index > 0 && <Divider style={styles.appDivider} />}
              <View style={styles.appItem}>
                <View style={styles.appHeader}>
                  <MaterialCommunityIcons name={app.appIcon as any} size={32} color="#666" />
                  <View style={styles.appInfo}>
                    <Text style={styles.appName}>{app.app}</Text>
                    <Text style={styles.appPackage}>{app.packageName}</Text>
                  </View>
                  <Switch
                    value={!app.isBlocked}
                    onValueChange={() => handleToggleAppBlock(app)}
                    color="#4caf50"
                  />
                </View>

                <View style={styles.appStats}>
                  <View style={styles.appStatRow}>
                    <Text style={styles.appStatLabel}>Downloaded:</Text>
                    <Text style={styles.appStatValue}>
                      {NetworkTrafficService.formatBytes(app.totalBytesIn)}
                    </Text>
                  </View>
                  <View style={styles.appStatRow}>
                    <Text style={styles.appStatLabel}>Uploaded:</Text>
                    <Text style={styles.appStatValue}>
                      {NetworkTrafficService.formatBytes(app.totalBytesOut)}
                    </Text>
                  </View>
                  <View style={styles.appStatRow}>
                    <Text style={styles.appStatLabel}>Connections:</Text>
                    <Text style={styles.appStatValue}>{app.connections}</Text>
                  </View>
                </View>

                {(app.suspiciousConnections > 0 || app.trackers.length > 0) && (
                  <View style={styles.appWarnings}>
                    {app.suspiciousConnections > 0 && (
                      <Chip icon="alert" mode="flat" style={styles.warningChip}>
                        {app.suspiciousConnections} Suspicious
                      </Chip>
                    )}
                    {app.trackers.length > 0 && (
                      <Chip icon="eye-off" mode="flat" style={styles.trackerChip}>
                        {app.trackers.length} Trackers
                      </Chip>
                    )}
                    {app.blockedConnections > 0 && (
                      <Chip icon="shield-check" mode="flat" style={styles.blockedChip}>
                        {app.blockedConnections} Blocked
                      </Chip>
                    )}
                  </View>
                )}
              </View>
            </View>
          ))}
        </Card.Content>
      </Card>
    </ScrollView>
  );

  const renderFirewallTab = () => (
    <ScrollView
      style={styles.tabContent}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={handleRefresh} />
      }
    >
      <Card style={styles.card}>
        <Card.Content>
          <View style={styles.firewallHeader}>
            <MaterialCommunityIcons name="security-network" size={40} color="#2196f3" />
            <View style={styles.firewallInfo}>
              <Text style={styles.firewallTitle}>App Firewall</Text>
              <Text style={styles.firewallDesc}>
                Control network access for individual apps
              </Text>
            </View>
          </View>
          <Button
            mode="contained"
            icon="plus"
            onPress={handleAddFirewallRule}
            style={styles.addButton}
          >
            Add Firewall Rule
          </Button>
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Active Rules" />
        <Card.Content>
          {firewallRules.length === 0 ? (
            <Text style={styles.emptyText}>No active firewall rules</Text>
          ) : (
            firewallRules.map((rule, index) => (
              <View key={rule.id}>
                {index > 0 && <Divider style={styles.ruleDivider} />}
                <View style={styles.ruleItem}>
                  <View style={styles.ruleHeader}>
                    <MaterialCommunityIcons name="shield" size={24} color="#2196f3" />
                    <View style={styles.ruleInfo}>
                      <Text style={styles.ruleName}>{rule.app}</Text>
                      <Text style={styles.rulePackage}>{rule.packageName}</Text>
                    </View>
                    <IconButton
                      icon="delete"
                      size={20}
                      onPress={() => handleDeleteFirewallRule(rule.id)}
                      iconColor="#f44336"
                    />
                    <Switch
                      value={rule.enabled}
                      color="#2196f3"
                    />
                  </View>
                  <View style={styles.ruleDetails}>
                    <Chip mode="flat" style={styles.ruleTypeChip}>
                      {rule.type.replace(/_/g, ' ').toUpperCase()}
                    </Chip>
                  </View>
                </View>
              </View>
            ))
          )}
        </Card.Content>
      </Card>
    </ScrollView>
  );

  const renderTrackersTab = () => (
    <ScrollView
      style={styles.tabContent}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={handleRefresh} />
      }
    >
      <Card style={styles.card}>
        <Card.Content>
          <View style={styles.trackerHeader}>
            <MaterialCommunityIcons name="eye-off" size={40} color="#4caf50" />
            <View style={styles.trackerInfo}>
              <Text style={styles.trackerTitle}>Tracker Blocking</Text>
              <Text style={styles.trackerDesc}>
                Network-level blocking of ads and trackers
              </Text>
            </View>
          </View>
          <View style={styles.trackerStats}>
            <View style={styles.trackerStatItem}>
              <Text style={styles.trackerStatValue}>
                {blockedTrackers.reduce((sum, t) => sum + t.blockedCount, 0)}
              </Text>
              <Text style={styles.trackerStatLabel}>Total Blocked</Text>
            </View>
            <View style={styles.trackerStatItem}>
              <Text style={styles.trackerStatValue}>{blockedTrackers.length}</Text>
              <Text style={styles.trackerStatLabel}>Unique Trackers</Text>
            </View>
          </View>
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Blocked Trackers" />
        <Card.Content>
          {blockedTrackers.map((tracker, index) => (
            <View key={tracker.domain}>
              {index > 0 && <Divider style={styles.trackerDivider} />}
              <View style={styles.trackerItem}>
                <View style={styles.trackerItemHeader}>
                  <MaterialCommunityIcons
                    name={
                      tracker.category === 'advertising' ? 'advertisements' :
                      tracker.category === 'analytics' ? 'chart-line' :
                      tracker.category === 'social' ? 'account-group' :
                      tracker.category === 'location' ? 'map-marker' :
                      'fingerprint'
                    }
                    size={24}
                    color="#f44336"
                  />
                  <View style={styles.trackerItemInfo}>
                    <Text style={styles.trackerDomain}>{tracker.domain}</Text>
                    <Text style={styles.trackerCategory}>
                      {tracker.category.charAt(0).toUpperCase() + tracker.category.slice(1)}
                    </Text>
                  </View>
                  <Chip mode="flat" style={styles.blockedCountChip}>
                    {tracker.blockedCount}
                  </Chip>
                </View>
                <View style={styles.trackerApps}>
                  <Text style={styles.trackerAppsLabel}>Apps:</Text>
                  <Text style={styles.trackerAppsText}>
                    {tracker.apps.join(', ')}
                  </Text>
                </View>
              </View>
            </View>
          ))}
        </Card.Content>
      </Card>
    </ScrollView>
  );

  const renderThreatsTab = () => (
    <ScrollView
      style={styles.tabContent}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={handleRefresh} />
      }
    >
      {/* Suspicious Activities */}
      <Card style={styles.card}>
        <Card.Title title="Suspicious Activities" />
        <Card.Content>
          {suspiciousActivities.length === 0 ? (
            <Text style={styles.emptyText}>No suspicious activities detected</Text>
          ) : (
            suspiciousActivities.map((activity, index) => (
              <View key={activity.id}>
                {index > 0 && <Divider style={styles.activityDivider} />}
                <View style={styles.activityItem}>
                  <View style={styles.activityHeader}>
                    <MaterialCommunityIcons name="alert-circle" size={24} color="#f44336" />
                    <View style={styles.activityInfo}>
                      <Text style={styles.activityApp}>{activity.app}</Text>
                      <Text style={styles.activityDest}>{activity.destination}</Text>
                    </View>
                    <Chip
                      mode="flat"
                      style={[
                        styles.severityChip,
                        {
                          backgroundColor:
                            activity.severity === 'critical' ? '#d32f2f' :
                            activity.severity === 'high' ? '#f44336' :
                            activity.severity === 'medium' ? '#ff9800' :
                            '#ffc107',
                        },
                      ]}
                      textStyle={styles.severityChipText}
                    >
                      {activity.severity.toUpperCase()}
                    </Chip>
                  </View>
                  <Text style={styles.activityDesc}>{activity.description}</Text>
                  <Text style={styles.activityRec}>
                    <MaterialCommunityIcons name="information" size={12} /> {activity.recommendation}
                  </Text>
                </View>
              </View>
            ))
          )}
        </Card.Content>
      </Card>

      {/* Suspicious Servers */}
      <Card style={styles.card}>
        <Card.Title title="Suspicious Servers" />
        <Card.Content>
          {suspiciousServers.map((server, index) => (
            <View key={server.ip}>
              {index > 0 && <Divider style={styles.serverDivider} />}
              <View style={styles.serverItem}>
                <View style={styles.serverHeader}>
                  <MaterialCommunityIcons name="server-security" size={24} color="#f44336" />
                  <View style={styles.serverInfo}>
                    <Text style={styles.serverDomain}>{server.domain}</Text>
                    <Text style={styles.serverIP}>{server.ip} ({server.country})</Text>
                  </View>
                </View>
                
                <View style={styles.serverDetails}>
                  <Chip icon="shield-alert" mode="flat" style={styles.reasonChip}>
                    {server.reason.toUpperCase()}
                  </Chip>
                  <Text style={styles.serverThreat}>
                    Threat Score: {server.threatScore}/100
                  </Text>
                </View>

                <View style={styles.serverStats}>
                  <Text style={styles.serverStat}>
                    {server.connections} connections from {server.apps.join(', ')}
                  </Text>
                </View>

                {!server.isBlocked && (
                  <Button
                    mode="contained"
                    icon="block-helper"
                    buttonColor="#f44336"
                    onPress={() => handleBlockServer(server)}
                    style={styles.blockButton}
                  >
                    Block Server
                  </Button>
                )}
                {server.isBlocked && (
                  <Chip icon="shield-check" mode="flat" style={styles.blockedServerChip}>
                    BLOCKED
                  </Chip>
                )}
              </View>
            </View>
          ))}
        </Card.Content>
      </Card>
    </ScrollView>
  );

  return (
    <View style={styles.container}>
      <SegmentedButtons
        value={activeTab}
        onValueChange={setActiveTab}
        buttons={[
          {
            value: 'monitor',
            label: 'Monitor',
            icon: 'monitor-eye',
          },
          {
            value: 'apps',
            label: 'Apps',
            icon: 'apps',
          },
          {
            value: 'firewall',
            label: 'Firewall',
            icon: 'firewall',
          },
          {
            value: 'trackers',
            label: 'Trackers',
            icon: 'eye-off',
          },
          {
            value: 'threats',
            label: 'Threats',
            icon: 'alert',
          },
        ]}
        style={styles.tabs}
      />

      {loading && !refreshing ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color="#2196f3" />
        </View>
      ) : (
        <>
          {activeTab === 'monitor' && renderMonitorTab()}
          {activeTab === 'apps' && renderAppsTab()}
          {activeTab === 'firewall' && renderFirewallTab()}
          {activeTab === 'trackers' && renderTrackersTab()}
          {activeTab === 'threats' && renderThreatsTab()}
        </>
      )}

      {/* Add Firewall Rule Dialog */}
      <Portal>
        <Dialog visible={showFirewallDialog} onDismiss={() => setShowFirewallDialog(false)}>
          <Dialog.Title>Add Firewall Rule</Dialog.Title>
          <Dialog.Content>
            <TextInput
              label="App Name"
              value={newRule.appName}
              onChangeText={(text) => setNewRule({ ...newRule, appName: text })}
              mode="outlined"
              style={{ marginBottom: 12 }}
              placeholder="e.g., Chrome, Facebook"
            />
            <TextInput
              label="Package Name"
              value={newRule.packageName}
              onChangeText={(text) => setNewRule({ ...newRule, packageName: text })}
              mode="outlined"
              style={{ marginBottom: 12 }}
              placeholder="e.g., com.android.chrome"
            />
            <Text style={{ fontSize: 14, fontWeight: '600', marginBottom: 8 }}>Rule Type</Text>
            <RadioButton.Group
              onValueChange={(value) => setNewRule({ ...newRule, ruleType: value as FirewallRule['type'] })}
              value={newRule.ruleType}>
              <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 8 }}>
                <RadioButton value="block_all" />
                <Text>Block All Network Access</Text>
              </View>
              <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 8 }}>
                <RadioButton value="wifi_only" />
                <Text>WiFi Only (Block Cellular)</Text>
              </View>
              <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 8 }}>
                <RadioButton value="cellular_only" />
                <Text>Cellular Only (Block WiFi)</Text>
              </View>
              <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                <RadioButton value="allow_all" />
                <Text>Allow All (Remove Restrictions)</Text>
              </View>
            </RadioButton.Group>
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setShowFirewallDialog(false)}>Cancel</Button>
            <Button onPress={handleSaveFirewallRule}>Add Rule</Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  tabs: {
    margin: 16,
  },
  tabContent: {
    flex: 1,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  card: {
    margin: 16,
    marginTop: 0,
  },
  badge: {
    backgroundColor: '#2196f3',
    marginRight: 16,
  },
  divider: {
    marginVertical: 12,
  },

  // Monitor tab
  monitoringControl: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  monitoringInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  monitoringText: {
    marginLeft: 12,
    flex: 1,
  },
  monitoringTitle: {
    fontSize: 16,
    fontWeight: '600',
  },
  monitoringStatus: {
    fontSize: 12,
    color: '#666',
    marginTop: 2,
  },
  statsGrid: {
    flexDirection: 'row',
    justifyContent: 'space-around',
  },
  statItem: {
    alignItems: 'center',
  },
  statValue: {
    fontSize: 24,
    fontWeight: 'bold',
    marginTop: 4,
  },
  statLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 2,
  },
  dataUsage: {
    marginTop: 12,
  },
  dataItem: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  dataLabel: {
    fontSize: 14,
    marginLeft: 8,
    flex: 1,
  },
  dataValue: {
    fontSize: 14,
    fontWeight: '600',
  },
  connectionDivider: {
    marginVertical: 12,
  },
  connectionItem: {
    paddingVertical: 8,
  },
  connectionHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  connectionApp: {
    flex: 1,
    fontSize: 16,
    fontWeight: '600',
    marginLeft: 8,
  },
  threatChip: {
    height: 24,
  },
  threatChipText: {
    fontSize: 10,
    color: '#fff',
    fontWeight: 'bold',
  },
  connectionDetails: {
    marginLeft: 32,
  },
  connectionText: {
    fontSize: 12,
    color: '#666',
    marginBottom: 4,
  },
  connectionStats: {
    flexDirection: 'row',
    gap: 12,
    marginTop: 4,
  },
  suspiciousRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginTop: 8,
    backgroundColor: '#ffebee',
    padding: 8,
    borderRadius: 4,
  },
  suspiciousText: {
    flex: 1,
    fontSize: 12,
    color: '#f44336',
    marginLeft: 4,
  },

  // Apps tab
  appDivider: {
    marginVertical: 16,
  },
  appItem: {
    paddingVertical: 8,
  },
  appHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 12,
  },
  appInfo: {
    flex: 1,
    marginLeft: 12,
  },
  appName: {
    fontSize: 16,
    fontWeight: '600',
  },
  appPackage: {
    fontSize: 11,
    color: '#666',
    marginTop: 2,
  },
  appStats: {
    marginLeft: 44,
    marginBottom: 8,
  },
  appStatRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 4,
  },
  appStatLabel: {
    fontSize: 13,
    color: '#666',
  },
  appStatValue: {
    fontSize: 13,
    fontWeight: '600',
  },
  appWarnings: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
    marginLeft: 44,
    marginTop: 8,
  },
  warningChip: {
    backgroundColor: '#fff3e0',
  },
  trackerChip: {
    backgroundColor: '#e3f2fd',
  },
  blockedChip: {
    backgroundColor: '#e8f5e9',
  },

  // Firewall tab
  firewallHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16,
  },
  firewallInfo: {
    flex: 1,
    marginLeft: 12,
  },
  firewallTitle: {
    fontSize: 18,
    fontWeight: '600',
  },
  firewallDesc: {
    fontSize: 13,
    color: '#666',
    marginTop: 2,
  },
  addButton: {
    marginTop: 8,
  },
  emptyText: {
    textAlign: 'center',
    color: '#666',
    fontSize: 14,
    padding: 16,
  },
  ruleDivider: {
    marginVertical: 12,
  },
  ruleItem: {
    paddingVertical: 8,
  },
  ruleHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  ruleInfo: {
    flex: 1,
    marginLeft: 12,
  },
  ruleName: {
    fontSize: 16,
    fontWeight: '600',
  },
  rulePackage: {
    fontSize: 11,
    color: '#666',
    marginTop: 2,
  },
  ruleDetails: {
    marginLeft: 36,
  },
  ruleTypeChip: {
    alignSelf: 'flex-start',
    backgroundColor: '#e3f2fd',
  },

  // Trackers tab
  trackerHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16,
  },
  trackerInfo: {
    flex: 1,
    marginLeft: 12,
  },
  trackerTitle: {
    fontSize: 18,
    fontWeight: '600',
  },
  trackerDesc: {
    fontSize: 13,
    color: '#666',
    marginTop: 2,
  },
  trackerStats: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginTop: 16,
  },
  trackerStatItem: {
    alignItems: 'center',
  },
  trackerStatValue: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#4caf50',
  },
  trackerStatLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  trackerDivider: {
    marginVertical: 12,
  },
  trackerItem: {
    paddingVertical: 8,
  },
  trackerItemHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  trackerItemInfo: {
    flex: 1,
    marginLeft: 12,
  },
  trackerDomain: {
    fontSize: 14,
    fontWeight: '600',
  },
  trackerCategory: {
    fontSize: 11,
    color: '#666',
    marginTop: 2,
  },
  blockedCountChip: {
    backgroundColor: '#e8f5e9',
  },
  trackerApps: {
    flexDirection: 'row',
    marginLeft: 36,
    marginTop: 4,
  },
  trackerAppsLabel: {
    fontSize: 12,
    color: '#666',
    marginRight: 4,
  },
  trackerAppsText: {
    flex: 1,
    fontSize: 12,
    color: '#666',
  },

  // Threats tab
  activityDivider: {
    marginVertical: 12,
  },
  activityItem: {
    paddingVertical: 8,
  },
  activityHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  activityInfo: {
    flex: 1,
    marginLeft: 12,
  },
  activityApp: {
    fontSize: 16,
    fontWeight: '600',
  },
  activityDest: {
    fontSize: 12,
    color: '#666',
    marginTop: 2,
  },
  severityChip: {
    height: 24,
  },
  severityChipText: {
    fontSize: 10,
    color: '#fff',
    fontWeight: 'bold',
  },
  activityDesc: {
    fontSize: 13,
    color: '#666',
    marginLeft: 36,
    marginBottom: 4,
  },
  activityRec: {
    fontSize: 12,
    color: '#2196f3',
    marginLeft: 36,
    fontStyle: 'italic',
  },
  serverDivider: {
    marginVertical: 16,
  },
  serverItem: {
    paddingVertical: 8,
  },
  serverHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  serverInfo: {
    flex: 1,
    marginLeft: 12,
  },
  serverDomain: {
    fontSize: 16,
    fontWeight: '600',
  },
  serverIP: {
    fontSize: 12,
    color: '#666',
    marginTop: 2,
  },
  serverDetails: {
    flexDirection: 'row',
    alignItems: 'center',
    marginLeft: 36,
    marginBottom: 8,
    gap: 12,
  },
  reasonChip: {
    backgroundColor: '#ffebee',
  },
  serverThreat: {
    fontSize: 13,
    fontWeight: '600',
    color: '#f44336',
  },
  serverStats: {
    marginLeft: 36,
    marginBottom: 8,
  },
  serverStat: {
    fontSize: 12,
    color: '#666',
  },
  blockButton: {
    marginLeft: 36,
    marginTop: 8,
  },
  blockedServerChip: {
    alignSelf: 'flex-start',
    marginLeft: 36,
    marginTop: 8,
    backgroundColor: '#e8f5e9',
  },
});
