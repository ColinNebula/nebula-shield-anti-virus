import React, {useEffect, useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  TouchableOpacity,
  Alert,
} from 'react-native';
import {
  Card,
  Button,
  Chip,
  useTheme,
  Divider,
  ProgressBar,
  SegmentedButtons,
  Surface,
} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import {
  PrivacyAuditService,
  PermissionUsage,
  DataBreach,
  PermissionRecommendation,
  PermissionAnalytics,
} from '../services/PrivacyAuditService';

const PrivacyAuditScreen = () => {
  const theme = useTheme();
  const [refreshing, setRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [permissionActivity, setPermissionActivity] = useState<PermissionUsage[]>([]);
  const [dataBreaches, setDataBreaches] = useState<DataBreach[]>([]);
  const [recommendations, setRecommendations] = useState<PermissionRecommendation[]>([]);
  const [analytics, setAnalytics] = useState<PermissionAnalytics | null>(null);

  useEffect(() => {
    loadPrivacyData();
  }, []);

  const loadPrivacyData = async () => {
    try {
      const [activity, breaches, recs, analyticsData] = await Promise.all([
        PrivacyAuditService.getTodayActivity(),
        PrivacyAuditService.checkDataBreaches(['user@example.com', 'user2@example.com']),
        PrivacyAuditService.getPermissionRecommendations(),
        PrivacyAuditService.getPermissionAnalytics(30),
      ]);
      setPermissionActivity(activity);
      setDataBreaches(breaches);
      setRecommendations(recs);
      setAnalytics(analyticsData);
    } catch (error) {
      console.error('Error loading privacy data:', error);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadPrivacyData();
    setRefreshing(false);
  };

  const handleRevokePermission = (rec: PermissionRecommendation) => {
    Alert.alert(
      'Revoke Permission',
      `Are you sure you want to revoke ${rec.permission} access for ${rec.app}?\n\n${rec.impact}`,
      [
        {text: 'Cancel', style: 'cancel'},
        {text: 'Revoke', style: 'destructive', onPress: () => {
          Alert.alert('Success', `${rec.permission} permission revoked for ${rec.app}`);
        }},
      ]
    );
  };

  const handleBreachAction = (breach: DataBreach) => {
    Alert.alert(
      `${breach.service} Data Breach`,
      breach.description + '\n\nRecommended Actions:\n' + breach.recommendations.map((r, i) => `${i + 1}. ${r}`).join('\n'),
      [
        {text: 'Dismiss'},
        {text: 'Change Password', onPress: () => {
          Alert.alert('Security', 'Opening password manager...');
        }},
      ]
    );
  };

  return (
    <ScrollView
      style={[styles.container, {backgroundColor: theme.colors.background}]}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}>
      {/* Header */}
      <Surface style={styles.header}>
        <Icon name="shield-account" size={40} color={theme.colors.primary} />
        <Text style={styles.headerTitle}>Privacy Audit</Text>
        <Text style={styles.headerSubtitle}>
          Comprehensive permission tracking & breach monitoring
        </Text>
      </Surface>

      {/* Tab Selection */}
      <View style={styles.tabContainer}>
        <SegmentedButtons
          value={activeTab}
          onValueChange={setActiveTab}
          buttons={[
            {value: 'overview', label: 'Overview', icon: 'view-dashboard'},
            {value: 'permissions', label: 'Permissions', icon: 'shield-key'},
            {value: 'breaches', label: 'Breaches', icon: 'alert-octagon'},
            {value: 'timeline', label: 'Timeline', icon: 'timeline'},
          ]}
          style={styles.segmentedButtons}
        />
      </View>

      {/* Overview Tab */}
      {activeTab === 'overview' && renderOverviewTab()}
      
      {/* Permissions Tab */}
      {activeTab === 'permissions' && renderPermissionsTab()}
      
      {/* Breaches Tab */}
      {activeTab === 'breaches' && renderBreachesTab()}
      
      {/* Timeline Tab */}
      {activeTab === 'timeline' && renderTimelineTab()}
    </ScrollView>
  );

  function renderOverviewTab() {
    return (
      <>
        {/* Quick Stats */}
        {analytics && (
          <Card style={styles.card}>
            <Card.Title 
              title="Permission Overview" 
              left={props => <Icon name="chart-box" {...props} />} 
            />
            <Card.Content>
              <View style={styles.statsGrid}>
                <View style={styles.statBox}>
                  <Text style={styles.statValue}>{analytics.grantedPermissions}</Text>
                  <Text style={styles.statLabel}>Granted</Text>
                </View>
                <View style={styles.statBox}>
                  <Text style={[styles.statValue, {color: '#f44336'}]}>{analytics.dangerousPermissions}</Text>
                  <Text style={styles.statLabel}>Dangerous</Text>
                </View>
                <View style={styles.statBox}>
                  <Text style={[styles.statValue, {color: '#ff9800'}]}>{recommendations.length}</Text>
                  <Text style={styles.statLabel}>To Review</Text>
                </View>
                <View style={styles.statBox}>
                  <Text style={[styles.statValue, {color: '#f44336'}]}>{dataBreaches.length}</Text>
                  <Text style={styles.statLabel}>Breaches</Text>
                </View>
              </View>
            </Card.Content>
          </Card>
        )}

        {/* Data Breaches Alert */}
        {dataBreaches.length > 0 && (
          <Card style={[styles.card, {backgroundColor: '#fff3e0'}]}>
            <Card.Content>
              <View style={styles.breachAlert}>
                <Icon name="alert-octagon" size={32} color="#f44336" />
                <View style={{flex: 1, marginLeft: 16}}>
                  <Text style={styles.breachAlertTitle}>
                    {dataBreaches.length} Data Breach{dataBreaches.length > 1 ? 'es' : ''} Detected!
                  </Text>
                  <Text style={styles.breachAlertText}>
                    Your accounts have been compromised. Take action now.
                  </Text>
                </View>
              </View>
            </Card.Content>
          </Card>
        )}

        {/* Top Recommendations */}
        {recommendations.length > 0 && (
          <Card style={styles.card}>
            <Card.Title 
              title="Priority Actions" 
              subtitle={`${recommendations.filter(r => r.action === 'revoke').length} permissions to revoke`}
              left={props => <Icon name="alert-circle" {...props} />} 
            />
            <Card.Content>
              {recommendations.slice(0, 3).map((rec, index) => (
                <View key={rec.id}>
                  <View style={styles.recItem}>
                    <View style={styles.recHeader}>
                      <Icon name={getAppIcon(rec.appIcon)} size={24} color={theme.colors.primary} />
                      <View style={{flex: 1, marginLeft: 12}}>
                        <Text style={styles.recApp}>{rec.app}</Text>
                        <Text style={styles.recPermission}>{rec.permission} Access</Text>
                      </View>
                      <Chip
                        compact
                        style={[styles.riskChip, {backgroundColor: getRiskColor(rec.riskLevel)}]}
                        textStyle={{color: '#fff', fontSize: 10}}>
                        {rec.riskLevel.toUpperCase()}
                      </Chip>
                    </View>
                    <Text style={styles.recReason}>{rec.reason}</Text>
                    <View style={styles.recActions}>
                      <Button
                        mode="text"
                        compact
                        onPress={() => Alert.alert('Info', rec.impact)}>
                        Impact
                      </Button>
                      <Button
                        mode="contained"
                        compact
                        buttonColor={rec.action === 'revoke' ? '#f44336' : '#ff9800'}
                        onPress={() => handleRevokePermission(rec)}>
                        {rec.action === 'revoke' ? 'Revoke' : 'Review'}
                      </Button>
                    </View>
                  </View>
                  {index < 2 && <Divider style={styles.recDivider} />}
                </View>
              ))}
            </Card.Content>
          </Card>
        )}

        {/* Recent Activity */}
        {permissionActivity.length > 0 && (
          <Card style={styles.card}>
            <Card.Title 
              title="Recent Activity" 
              subtitle="Last 8 hours"
              left={props => <Icon name="history" {...props} />} 
            />
            <Card.Content>
              {permissionActivity.slice(0, 5).map((activity, index) => (
                <View key={activity.id}>
                  <View style={styles.activityItem}>
                    <Icon name={PrivacyAuditService.getPermissionIcon(activity.permission)} size={20} color={theme.colors.primary} />
                    <View style={{flex: 1, marginLeft: 12}}>
                      <Text style={styles.activityApp}>{activity.app}</Text>
                      <Text style={styles.activityText}>
                        {activity.permissionName} • {PrivacyAuditService.formatTimeAgo(activity.timestamp)}
                      </Text>
                    </View>
                    {activity.isSuspicious && (
                      <Chip compact style={{backgroundColor: '#ff9800'}} textStyle={{color: '#fff', fontSize: 10}}>
                        SUSPICIOUS
                      </Chip>
                    )}
                  </View>
                  {index < 4 && <Divider style={styles.activityDivider} />}
                </View>
              ))}
            </Card.Content>
          </Card>
        )}
      </>
    );
  }

  function renderPermissionsTab() {
    return (
      <>
        {/* Permission Analytics */}
        {analytics && (
          <>
            <Card style={styles.card}>
              <Card.Title 
                title="Permission Breakdown" 
                left={props => <Icon name="chart-donut" {...props} />} 
              />
              <Card.Content>
                {Object.entries(analytics.byType).map(([type, data]) => (
                  <View key={type} style={styles.permTypeItem}>
                    <View style={styles.permTypeHeader}>
                      <Icon name={getPermissionTypeIcon(type)} size={24} color={theme.colors.primary} />
                      <Text style={styles.permTypeName}>{type.charAt(0).toUpperCase() + type.slice(1)}</Text>
                      <Chip compact>{data.count} apps</Chip>
                    </View>
                    <View style={styles.permTypeDetails}>
                      <Text style={styles.permTypeText}>
                        Last used: {PrivacyAuditService.formatTimeAgo(data.lastUsed)}
                      </Text>
                      <ProgressBar 
                        progress={data.riskScore / 100} 
                        color={data.riskScore > 70 ? '#f44336' : data.riskScore > 50 ? '#ff9800' : '#4caf50'}
                        style={styles.riskBar}
                      />
                      <Text style={styles.riskScore}>Risk Score: {data.riskScore}/100</Text>
                    </View>
                    <View style={styles.permTypeApps}>
                      <Text style={styles.permTypeAppsLabel}>Apps:</Text>
                      <Text style={styles.permTypeAppsList}>{data.apps.join(', ')}</Text>
                    </View>
                  </View>
                ))}
              </Card.Content>
            </Card>

            {/* All Recommendations */}
            <Card style={styles.card}>
              <Card.Title 
                title={`All Recommendations (${recommendations.length})`}
                left={props => <Icon name="lightbulb-on" {...props} />} 
              />
              <Card.Content>
                {recommendations.map((rec, index) => (
                  <View key={rec.id}>
                    <View style={styles.recItem}>
                      <View style={styles.recHeader}>
                        <Icon name={getAppIcon(rec.appIcon)} size={24} color={theme.colors.primary} />
                        <View style={{flex: 1, marginLeft: 12}}>
                          <Text style={styles.recApp}>{rec.app}</Text>
                          <Text style={styles.recPermission}>{rec.permission} Access</Text>
                          <Text style={styles.recUsage}>Used: {rec.usageFrequency}</Text>
                        </View>
                        <Chip
                          compact
                          style={[styles.riskChip, {backgroundColor: getRiskColor(rec.riskLevel)}]}
                          textStyle={{color: '#fff', fontSize: 10}}>
                          {rec.riskLevel.toUpperCase()}
                        </Chip>
                      </View>
                      <Text style={styles.recReason}>{rec.reason}</Text>
                      <Text style={styles.recLastUsed}>
                        Last used: {PrivacyAuditService.formatTimeAgo(rec.lastUsed)}
                      </Text>
                      <View style={styles.recActions}>
                        <Button
                          mode="text"
                          compact
                          onPress={() => Alert.alert('Impact', rec.impact)}>
                          View Impact
                        </Button>
                        <Button
                          mode="contained"
                          compact
                          buttonColor={rec.action === 'revoke' ? '#f44336' : '#ff9800'}
                          onPress={() => handleRevokePermission(rec)}>
                          {rec.action === 'revoke' ? 'Revoke Now' : 'Review'}
                        </Button>
                      </View>
                    </View>
                    {index < recommendations.length - 1 && <Divider style={styles.recDivider} />}
                  </View>
                ))}
              </Card.Content>
            </Card>
          </>
        )}
      </>
    );
  }

  function renderBreachesTab() {
    return (
      <>
        {dataBreaches.length === 0 ? (
          <Card style={styles.card}>
            <Card.Content>
              <View style={styles.noBreachesContainer}>
                <Icon name="shield-check" size={64} color="#4caf50" />
                <Text style={styles.noBreachesTitle}>No Breaches Detected</Text>
                <Text style={styles.noBreachesText}>
                  Your accounts appear safe. We'll monitor and alert you if any breaches are detected.
                </Text>
              </View>
            </Card.Content>
          </Card>
        ) : (
          <>
            {dataBreaches.map((breach, index) => (
              <Card key={breach.id} style={styles.card}>
                <Card.Content>
                  <View style={styles.breachCard}>
                    <View style={styles.breachHeader}>
                      <Icon name={getAppIcon(breach.serviceIcon)} size={32} color="#f44336" />
                      <View style={{flex: 1, marginLeft: 16}}>
                        <Text style={styles.breachService}>{breach.service} Data Breach</Text>
                        <Chip
                          compact
                          style={[styles.severityChip, {backgroundColor: getSeverityColor(breach.severity)}]}
                          textStyle={{color: '#fff'}}>
                          {breach.severity.toUpperCase()} SEVERITY
                        </Chip>
                      </View>
                    </View>

                    <View style={styles.breachDetails}>
                      <View style={styles.breachRow}>
                        <Text style={styles.breachLabel}>Breach Date:</Text>
                        <Text style={styles.breachValue}>{breach.breachDate}</Text>
                      </View>
                      <View style={styles.breachRow}>
                        <Text style={styles.breachLabel}>Discovered:</Text>
                        <Text style={styles.breachValue}>{breach.discoveredDate}</Text>
                      </View>
                      <View style={styles.breachRow}>
                        <Text style={styles.breachLabel}>Affected Accounts:</Text>
                        <Text style={styles.breachValue}>{breach.affectedAccounts.toLocaleString()}</Text>
                      </View>
                      <View style={styles.breachRow}>
                        <Text style={styles.breachLabel}>Your Email:</Text>
                        <Text style={styles.breachValue}>{breach.email}</Text>
                      </View>
                    </View>

                    <View style={styles.dataTypesContainer}>
                      <Text style={styles.dataTypesLabel}>Compromised Data:</Text>
                      <View style={styles.dataTypes}>
                        {breach.dataTypes.map((type, i) => (
                          <Chip key={i} compact style={styles.dataTypeChip}>{type}</Chip>
                        ))}
                      </View>
                    </View>

                    <Text style={styles.breachDescription}>{breach.description}</Text>

                    <View style={styles.recommendationsBox}>
                      <Text style={styles.recommendationsTitle}>🔒 Recommended Actions:</Text>
                      {breach.recommendations.map((rec, i) => (
                        <Text key={i} style={styles.recommendationText}>
                          {i + 1}. {rec}
                        </Text>
                      ))}
                    </View>

                    <View style={styles.breachActions}>
                      <Button
                        mode="contained"
                        buttonColor="#f44336"
                        onPress={() => handleBreachAction(breach)}
                        style={{flex: 1}}>
                        Take Action
                      </Button>
                      {!breach.isPasswordChanged && (
                        <Button
                          mode="outlined"
                          onPress={() => Alert.alert('Success', 'Password change marked as complete')}
                          style={{flex: 1, marginLeft: 8}}>
                          Mark Changed
                        </Button>
                      )}
                    </View>
                  </View>
                </Card.Content>
              </Card>
            ))}
          </>
        )}
      </>
    );
  }

  function renderTimelineTab() {
    const groupedActivity = groupByDate(permissionActivity);
    
    return (
      <>
        {Object.entries(groupedActivity).map(([date, activities]) => (
          <Card key={date} style={styles.card}>
            <Card.Title 
              title={formatDate(date)}
              subtitle={`${activities.length} permission access${activities.length > 1 ? 'es' : ''}`}
              left={props => <Icon name="calendar" {...props} />} 
            />
            <Card.Content>
              {activities.map((activity, index) => (
                <View key={activity.id}>
                  <View style={styles.timelineItem}>
                    <View style={styles.timelineDot} />
                    <View style={styles.timelineContent}>
                      <View style={styles.timelineHeader}>
                        <Icon name={PrivacyAuditService.getPermissionIcon(activity.permission)} size={20} color={theme.colors.primary} />
                        <Text style={styles.timelineApp}>{activity.app}</Text>
                        <Text style={styles.timelineTime}>
                          {new Date(activity.timestamp).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})}
                        </Text>
                      </View>
                      <Text style={styles.timelineText}>
                        Accessed <Text style={{fontWeight: 'bold'}}>{activity.permissionName}</Text>
                        {activity.location && ` at ${activity.location}`}
                      </Text>
                      <View style={styles.timelineDetails}>
                        <Text style={styles.timelineDetail}>Duration: {activity.duration}s</Text>
                        <Text style={styles.timelineDetail}>Frequency: {activity.frequency}x today</Text>
                        {activity.isSuspicious && (
                          <Chip compact style={{backgroundColor: '#ff9800', marginLeft: 8}} textStyle={{color: '#fff', fontSize: 9}}>
                            SUSPICIOUS
                          </Chip>
                        )}
                      </View>
                    </View>
                  </View>
                  {index < activities.length - 1 && <View style={styles.timelineLine} />}
                </View>
              ))}
            </Card.Content>
          </Card>
        ))}
      </>
    );
  }

  function groupByDate(activities: PermissionUsage[]): { [date: string]: PermissionUsage[] } {
    const grouped: { [date: string]: PermissionUsage[] } = {};
    activities.forEach(activity => {
      const date = activity.timestamp.split('T')[0];
      if (!grouped[date]) grouped[date] = [];
      grouped[date].push(activity);
    });
    return grouped;
  }

  function formatDate(dateStr: string): string {
    const date = new Date(dateStr);
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);

    if (date.toDateString() === today.toDateString()) return 'Today';
    if (date.toDateString() === yesterday.toDateString()) return 'Yesterday';
    return date.toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' });
  }

  function getAppIcon(icon: string): any {
    const icons: { [key: string]: string } = {
      instagram: 'instagram',
      facebook: 'facebook',
      whatsapp: 'whatsapp',
      twitter: 'twitter',
      linkedin: 'linkedin',
      adobe: 'adobe',
      'weather-partly-cloudy': 'weather-partly-cloudy',
      flashlight: 'flashlight',
      shopping: 'shopping',
      'gamepad-variant': 'gamepad-variant',
      camera: 'camera',
      microphone: 'microphone',
    };
    return icons[icon] || 'application';
  }

  function getPermissionTypeIcon(type: string): string {
    const icons: { [key: string]: string } = {
      camera: 'camera',
      microphone: 'microphone',
      location: 'map-marker',
      contacts: 'account-multiple',
      photos: 'image-multiple',
    };
    return icons[type] || 'shield-key';
  }

  function getRiskColor(level: string): string {
    switch (level) {
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      case 'low': return '#4caf50';
      default: return '#9e9e9e';
    }
  }

  function getSeverityColor(severity: string): string {
    switch (severity) {
      case 'critical': return '#b71c1c';
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      case 'low': return '#ffc107';
      default: return '#9e9e9e';
    }
  }
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  header: {
    padding: 20,
    alignItems: 'center',
    elevation: 2,
    marginBottom: 16,
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    marginTop: 12,
  },
  headerSubtitle: {
    fontSize: 14,
    color: '#666',
    marginTop: 4,
    textAlign: 'center',
  },
  tabContainer: {
    paddingHorizontal: 12,
    marginBottom: 16,
  },
  segmentedButtons: {
    marginBottom: 0,
  },
  card: {
    margin: 12,
    marginTop: 0,
    marginBottom: 16,
  },
  statsGrid: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    flexWrap: 'wrap',
  },
  statBox: {
    alignItems: 'center',
    minWidth: '22%',
    marginBottom: 8,
  },
  statValue: {
    fontSize: 24,
    fontWeight: 'bold',
  },
  statLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  breachAlert: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  breachAlertTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#f44336',
    marginBottom: 4,
  },
  breachAlertText: {
    fontSize: 14,
    color: '#666',
  },
  recItem: {
    paddingVertical: 12,
  },
  recHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  recApp: {
    fontSize: 16,
    fontWeight: '600',
  },
  recPermission: {
    fontSize: 14,
    color: '#666',
  },
  recUsage: {
    fontSize: 12,
    color: '#999',
    marginTop: 2,
  },
  recReason: {
    fontSize: 14,
    color: '#666',
    marginBottom: 4,
  },
  recLastUsed: {
    fontSize: 12,
    color: '#999',
    marginBottom: 8,
  },
  recActions: {
    flexDirection: 'row',
    justifyContent: 'flex-end',
    gap: 8,
  },
  recDivider: {
    marginVertical: 8,
  },
  riskChip: {
    height: 20,
  },
  activityItem: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 12,
  },
  activityApp: {
    fontSize: 16,
    fontWeight: '600',
  },
  activityText: {
    fontSize: 13,
    color: '#666',
    marginTop: 2,
  },
  activityDivider: {
    marginVertical: 4,
  },
  permTypeItem: {
    marginBottom: 16,
    padding: 12,
    backgroundColor: '#f5f5f5',
    borderRadius: 8,
  },
  permTypeHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
    gap: 12,
  },
  permTypeName: {
    flex: 1,
    fontSize: 16,
    fontWeight: '600',
  },
  permTypeDetails: {
    marginTop: 8,
  },
  permTypeText: {
    fontSize: 13,
    color: '#666',
    marginBottom: 4,
  },
  riskBar: {
    height: 6,
    borderRadius: 3,
    marginVertical: 4,
  },
  riskScore: {
    fontSize: 12,
    color: '#666',
    textAlign: 'right',
  },
  permTypeApps: {
    marginTop: 8,
  },
  permTypeAppsLabel: {
    fontSize: 12,
    fontWeight: '600',
    marginBottom: 4,
  },
  permTypeAppsList: {
    fontSize: 12,
    color: '#666',
  },
  noBreachesContainer: {
    alignItems: 'center',
    paddingVertical: 40,
  },
  noBreachesTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    marginTop: 16,
    marginBottom: 8,
  },
  noBreachesText: {
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
    paddingHorizontal: 20,
  },
  breachCard: {
    paddingVertical: 8,
  },
  breachHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16,
  },
  breachService: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 8,
  },
  severityChip: {
    alignSelf: 'flex-start',
  },
  breachDetails: {
    backgroundColor: '#f5f5f5',
    padding: 12,
    borderRadius: 8,
    marginBottom: 12,
  },
  breachRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 8,
  },
  breachLabel: {
    fontSize: 14,
    color: '#666',
  },
  breachValue: {
    fontSize: 14,
    fontWeight: '600',
  },
  dataTypesContainer: {
    marginBottom: 12,
  },
  dataTypesLabel: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 8,
  },
  dataTypes: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
  dataTypeChip: {
    backgroundColor: '#e3f2fd',
  },
  breachDescription: {
    fontSize: 14,
    color: '#666',
    lineHeight: 20,
    marginBottom: 16,
  },
  recommendationsBox: {
    backgroundColor: '#fff3e0',
    padding: 12,
    borderRadius: 8,
    marginBottom: 16,
  },
  recommendationsTitle: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 8,
  },
  recommendationText: {
    fontSize: 13,
    color: '#666',
    marginBottom: 4,
  },
  breachActions: {
    flexDirection: 'row',
    gap: 8,
  },
  timelineItem: {
    flexDirection: 'row',
    paddingVertical: 8,
  },
  timelineDot: {
    width: 12,
    height: 12,
    borderRadius: 6,
    backgroundColor: '#2196f3',
    marginTop: 4,
    marginRight: 12,
  },
  timelineContent: {
    flex: 1,
  },
  timelineHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 4,
  },
  timelineApp: {
    flex: 1,
    fontSize: 16,
    fontWeight: '600',
  },
  timelineTime: {
    fontSize: 12,
    color: '#999',
  },
  timelineText: {
    fontSize: 14,
    color: '#666',
    marginBottom: 4,
  },
  timelineDetails: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  timelineDetail: {
    fontSize: 12,
    color: '#999',
  },
  timelineLine: {
    width: 2,
    height: 20,
    backgroundColor: '#e0e0e0',
    marginLeft: 5,
  },
});

export default PrivacyAuditScreen;
