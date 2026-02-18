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
import {Card, Button, Surface, useTheme, Switch, SegmentedButtons, Chip, Divider, ProgressBar, IconButton} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import VPNService, {VPNServer, VPNStatus, BlockedStats} from '../services/VPNService';

const VPNScreen = (): JSX.Element => {
  const theme = useTheme();
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [vpnStatus, setVpnStatus] = useState<VPNStatus | null>(null);
  const [servers, setServers] = useState<VPNServer[]>([]);
  const [recommendedServer, setRecommendedServer] = useState<VPNServer | null>(null);
  const [selectedTab, setSelectedTab] = useState('status');
  const [showServerList, setShowServerList] = useState(false);
  const [blockedStats, setBlockedStats] = useState<BlockedStats | null>(null);
  const [speedTestRunning, setSpeedTestRunning] = useState(false);

  useEffect(() => {
    loadVPNData();
    
    // Poll for status updates every 2 seconds when connected
    const interval = setInterval(() => {
      if (vpnStatus?.connected) {
        loadVPNStatus();
        loadBlockedStats();
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [vpnStatus?.connected]);

  const loadVPNData = async () => {
    await Promise.all([
      loadServers(),
      loadVPNStatus(),
      loadBlockedStats(),
    ]);
  };

  const loadServers = async () => {
    const result = await VPNService.getServers();
    if (result.success && result.data) {
      setServers(result.data.servers || []);
      setRecommendedServer(result.data.recommended || null);
    }
  };

  const loadVPNStatus = async () => {
    const result = await VPNService.getStatus();
    if (result.success && result.data) {
      setVpnStatus(result.data);
    }
  };

  const loadBlockedStats = async () => {
    const result = await VPNService.getBlockedStats();
    if (result.success && result.data) {
      setBlockedStats(result.data.stats);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadVPNData();
    setRefreshing(false);
  };

  const handleConnect = async (serverId?: string) => {
    setLoading(true);
    const targetServerId = serverId || recommendedServer?.id;
    
    if (!targetServerId) {
      Alert.alert('Error', 'No server selected');
      setLoading(false);
      return;
    }

    const result = await VPNService.connect(targetServerId, {
      killSwitch: vpnStatus?.killSwitch ?? true,
      dnsLeakProtection: vpnStatus?.dnsLeakProtection ?? true,
      protocol: vpnStatus?.protocol ?? 'WireGuard',
    });

    if (result.success) {
      Alert.alert('Connected', result.data?.message || 'Connected to VPN');
      await loadVPNStatus();
      setShowServerList(false);
    } else {
      Alert.alert('Connection Failed', result.error || 'Failed to connect');
    }
    setLoading(false);
  };

  const handleDisconnect = async () => {
    setLoading(true);
    const result = await VPNService.disconnect();
    
    if (result.success) {
      Alert.alert('Disconnected', 'Disconnected from VPN');
      await loadVPNStatus();
    } else {
      Alert.alert('Error', result.error || 'Failed to disconnect');
    }
    setLoading(false);
  };

  const handleToggleKillSwitch = async (enabled: boolean) => {
    const result = await VPNService.toggleKillSwitch(enabled);
    if (result.success) {
      await loadVPNStatus();
    }
  };

  const handleToggleDNSProtection = async (enabled: boolean) => {
    const result = await VPNService.toggleDNSLeakProtection(enabled);
    if (result.success) {
      await loadVPNStatus();
    }
  };

  const handleToggleSplitTunneling = async (enabled: boolean) => {
    const result = await VPNService.toggleSplitTunneling(enabled);
    if (result.success) {
      await loadVPNStatus();
    }
  };

  const handleProtocolChange = async (value: string) => {
    const result = await VPNService.setProtocol(value as 'WireGuard' | 'OpenVPN');
    if (result.success) {
      await loadVPNStatus();
    }
  };

  const handleDNSLeakTest = async () => {
    setLoading(true);
    const result = await VPNService.dnsLeakTest();
    setLoading(false);
    
    if (result.success && result.data) {
      const icon = result.data.leakDetected ? '⚠️' : '✅';
      Alert.alert(`${icon} DNS Leak Test`, result.data.message);
    }
  };

  const handleSpeedTest = async () => {
    if (!vpnStatus?.connected) {
      Alert.alert('Not Connected', 'Please connect to VPN first');
      return;
    }
    
    setSpeedTestRunning(true);
    const result = await VPNService.runSpeedTest();
    setSpeedTestRunning(false);
    
    if (result.success && result.data?.results) {
      const { download, upload, ping } = result.data.results;
      Alert.alert(
        '🚀 Speed Test Results',
        `Download: ${download} Mbps\nUpload: ${upload} Mbps\nPing: ${ping} ms`
      );
      await loadVPNStatus();
    }
  };

  const handleToggleFavorite = async (serverId: string, isFavorite: boolean) => {
    if (isFavorite) {
      await VPNService.removeFavorite(serverId);
    } else {
      await VPNService.addFavorite(serverId);
    }
    await loadServers();
  };

  const handleToggleAutoReconnect = async (enabled: boolean) => {
    const result = await VPNService.toggleAutoReconnect(enabled);
    if (result.success) {
      await loadVPNStatus();
    }
  };

  const handleToggleAdBlocking = async (enabled: boolean) => {
    const result = await VPNService.toggleAdBlocking(enabled);
    if (result.success) {
      await loadVPNStatus();
    }
  };

  const handleToggleMalwareBlocking = async (enabled: boolean) => {
    const result = await VPNService.toggleMalwareBlocking(enabled);
    if (result.success) {
      await loadVPNStatus();
    }
  };

  const handleToggleTrackerBlocking = async (enabled: boolean) => {
    const result = await VPNService.toggleTrackerBlocking(enabled);
    if (result.success) {
      await loadVPNStatus();
    }
  };

  const handleToggleObfuscation = async (enabled: boolean) => {
    const result = await VPNService.toggleObfuscation(enabled);
    if (result.success) {
      await loadVPNStatus();
    } else {
      Alert.alert('Error', result.error || 'Failed to toggle obfuscation');
    }
  };

  const handleToggleIPv6Protection = async (enabled: boolean) => {
    const result = await VPNService.toggleIPv6Protection(enabled);
    if (result.success) {
      await loadVPNStatus();
    }
  };

  const getStatusColor = () => {
    if (!vpnStatus) return theme.colors.surfaceVariant;
    switch (vpnStatus.status) {
      case 'connected': return '#4caf50';
      case 'connecting': return '#ff9800';
      case 'disconnecting': return '#ff9800';
      default: return '#f44336';
    }
  };

  const getStatusIcon = () => {
    if (!vpnStatus) return 'shield-off';
    switch (vpnStatus.status) {
      case 'connected': return 'shield-check';
      case 'connecting': return 'shield-sync';
      case 'disconnecting': return 'shield-sync';
      default: return 'shield-off';
    }
  };

  const renderStatusTab = () => (
    <View>
      {/* Connection Status Card */}
      <Card style={styles.card}>
        <Card.Content>
          <View style={styles.statusContainer}>
            <Icon name={getStatusIcon()} size={80} color={getStatusColor()} />
            <Text style={[styles.statusText, {color: getStatusColor()}]}>
              {vpnStatus?.status.toUpperCase() || 'DISCONNECTED'}
            </Text>
            {vpnStatus?.server && (
              <Text style={styles.serverText}>
                {vpnStatus.server.flag} {vpnStatus.server.name}
              </Text>
            )}
          </View>

          {vpnStatus?.connected ? (
            <Button
              mode="contained"
              onPress={handleDisconnect}
              loading={loading}
              disabled={loading}
              buttonColor="#f44336"
              style={styles.button}>
              Disconnect
            </Button>
          ) : (
            <Button
              mode="contained"
              onPress={() => handleConnect()}
              loading={loading}
              disabled={loading}
              buttonColor="#4caf50"
              style={styles.button}>
              Quick Connect
            </Button>
          )}

          <Button
            mode="outlined"
            onPress={() => setShowServerList(!showServerList)}
            style={styles.button}>
            {showServerList ? 'Hide Servers' : 'Choose Server'}
          </Button>
        </Card.Content>
      </Card>

      {/* Connection Stats */}
      {vpnStatus?.connected && (
        <Card style={styles.card}>
          <Card.Title title="Connection Statistics" />
          <Card.Content>
            <View style={styles.statRow}>
              <Icon name="clock-outline" size={24} color={theme.colors.primary} />
              <Text style={styles.statLabel}>Duration:</Text>
              <Text style={styles.statValue}>
                {VPNService.formatDuration(vpnStatus.duration)}
              </Text>
            </View>
            <View style={styles.statRow}>
              <Icon name="upload" size={24} color={theme.colors.primary} />
              <Text style={styles.statLabel}>Sent:</Text>
              <Text style={styles.statValue}>
                {VPNService.formatBytes(vpnStatus.bytesSent)}
              </Text>
            </View>
            <View style={styles.statRow}>
              <Icon name="download" size={24} color={theme.colors.primary} />
              <Text style={styles.statLabel}>Received:</Text>
              <Text style={styles.statValue}>
                {VPNService.formatBytes(vpnStatus.bytesReceived)}
              </Text>
            </View>
            <View style={styles.statRow}>
              <Icon name="ip" size={24} color={theme.colors.primary} />
              <Text style={styles.statLabel}>Public IP:</Text>
              <Text style={styles.statValue}>{vpnStatus.publicIP}</Text>
            </View>
          </Card.Content>
        </Card>
      )}

      {/* Blocked Content Stats */}
      {vpnStatus?.connected && blockedStats && (
        <Card style={styles.card}>
          <Card.Title 
            title="Protected Content" 
            subtitle={`${blockedStats.totalBlocked} items blocked`}
          />
          <Card.Content>
            <View style={styles.blockedStatRow}>
              <Icon name="shield-check" size={32} color="#4caf50" />
              <View style={styles.blockedStatInfo}>
                <Text style={styles.blockedStatLabel}>Ads Blocked</Text>
                <Text style={styles.blockedStatValue}>{blockedStats.adsBlocked}</Text>
              </View>
            </View>
            <View style={styles.blockedStatRow}>
              <Icon name="eye-off" size={32} color="#2196f3" />
              <View style={styles.blockedStatInfo}>
                <Text style={styles.blockedStatLabel}>Trackers Blocked</Text>
                <Text style={styles.blockedStatValue}>{blockedStats.trackersBlocked}</Text>
              </View>
            </View>
            <View style={styles.blockedStatRow}>
              <Icon name="bug" size={32} color="#f44336" />
              <View style={styles.blockedStatInfo}>
                <Text style={styles.blockedStatLabel}>Malware Blocked</Text>
                <Text style={styles.blockedStatValue}>{blockedStats.malwareBlocked}</Text>
              </View>
            </View>
          </Card.Content>
        </Card>
      )}

      {/* Speed Test */}
      {vpnStatus?.connected && (
        <Card style={styles.card}>
          <Card.Title title="Speed Test" />
          <Card.Content>
            {vpnStatus.speedTest && (
              <View style={styles.speedTestResults}>
                <View style={styles.speedMetric}>
                  <Icon name="download" size={24} color={theme.colors.primary} />
                  <Text style={styles.speedLabel}>Download</Text>
                  <Text style={styles.speedValue}>{vpnStatus.speedTest.download} Mbps</Text>
                </View>
                <View style={styles.speedMetric}>
                  <Icon name="upload" size={24} color={theme.colors.primary} />
                  <Text style={styles.speedLabel}>Upload</Text>
                  <Text style={styles.speedValue}>{vpnStatus.speedTest.upload} Mbps</Text>
                </View>
                <View style={styles.speedMetric}>
                  <Icon name="timer" size={24} color={theme.colors.primary} />
                  <Text style={styles.speedLabel}>Ping</Text>
                  <Text style={styles.speedValue}>{vpnStatus.speedTest.ping} ms</Text>
                </View>
              </View>
            )}
            <Button
              mode="contained"
              onPress={handleSpeedTest}
              loading={speedTestRunning}
              disabled={speedTestRunning}
              icon="speedometer"
              style={styles.button}>
              {speedTestRunning ? 'Testing...' : 'Run Speed Test'}
            </Button>
          </Card.Content>
        </Card>
      )}

      {/* Server List */}
      {showServerList && (
        <Card style={styles.card}>
          <Card.Title title="Available Servers" />
          <Card.Content>
            {recommendedServer && (
              <View>
                <Text style={styles.sectionTitle}>⭐ Recommended</Text>
                <TouchableOpacity
                  style={[styles.serverItem, {backgroundColor: theme.colors.primaryContainer}]}
                  onPress={() => handleConnect(recommendedServer.id)}
                  disabled={loading}>
                  <Text style={styles.serverFlag}>{recommendedServer.flag}</Text>
                  <View style={styles.serverInfo}>
                    <Text style={styles.serverName}>{recommendedServer.name}</Text>
                    <Text style={styles.serverDetails}>
                      {recommendedServer.latency}ms • Load: {recommendedServer.load}%
                    </Text>
                  </View>
                  <Chip compact>{recommendedServer.status}</Chip>
                </TouchableOpacity>
                <Divider style={styles.divider} />
              </View>
            )}
            <Text style={styles.sectionTitle}>All Servers</Text>
            {servers.map((server) => (
              <TouchableOpacity
                key={server.id}
                style={[
                  styles.serverItem,
                  server.id === vpnStatus?.server?.id && {
                    backgroundColor: theme.colors.primaryContainer,
                  },
                ]}
                onPress={() => handleConnect(server.id)}
                disabled={loading || server.status !== 'online'}>
                <Text style={styles.serverFlag}>{server.flag}</Text>
                <View style={styles.serverInfo}>
                  <Text style={styles.serverName}>{server.name}</Text>
                  <Text style={styles.serverDetails}>
                    {server.latency}ms • Load: {server.load}% • {server.bandwidth}
                  </Text>
                  <View style={styles.featureChips}>
                    {server.features.map((feature) => (
                      <Chip key={feature} compact style={styles.featureChip}>
                        {feature}
                      </Chip>
                    ))}
                  </View>
                </View>
                <View style={styles.serverActions}>
                  <IconButton
                    icon={server.isFavorite ? 'star' : 'star-outline'}
                    size={20}
                    iconColor={server.isFavorite ? '#ffd700' : theme.colors.onSurface}
                    onPress={() => handleToggleFavorite(server.id, server.isFavorite || false)}
                  />
                  <Chip compact mode={server.status === 'online' ? 'flat' : 'outlined'}>
                    {server.status}
                  </Chip>
                </View>
              </TouchableOpacity>
            ))}
          </Card.Content>
        </Card>
      )}
    </View>
  );

  const renderSettingsTab = () => (
    <View>
      {/* Security Settings */}
      <Card style={styles.card}>
        <Card.Title title="Security Settings" />
        <Card.Content>
          <View style={styles.settingRow}>
            <View style={styles.settingInfo}>
              <Text style={styles.settingTitle}>Kill Switch</Text>
              <Text style={styles.settingDescription}>
                Block internet if VPN disconnects
              </Text>
            </View>
            <Switch
              value={vpnStatus?.killSwitch ?? true}
              onValueChange={handleToggleKillSwitch}
            />
          </View>
          <Divider />
          <View style={styles.settingRow}>
            <View style={styles.settingInfo}>
              <Text style={styles.settingTitle}>DNS Leak Protection</Text>
              <Text style={styles.settingDescription}>
                Prevent DNS queries from leaking
              </Text>
            </View>
            <Switch
              value={vpnStatus?.dnsLeakProtection ?? true}
              onValueChange={handleToggleDNSProtection}
            />
          </View>
          <Divider />
          <View style={styles.settingRow}>
            <View style={styles.settingInfo}>
              <Text style={styles.settingTitle}>IPv6 Protection</Text>
              <Text style={styles.settingDescription}>
                Prevent IPv6 address leaks
              </Text>
            </View>
            <Switch
              value={vpnStatus?.ipv6Protection ?? true}
              onValueChange={handleToggleIPv6Protection}
            />
          </View>
          <Divider />
          <View style={styles.settingRow}>
            <View style={styles.settingInfo}>
              <Text style={styles.settingTitle}>Auto-Reconnect</Text>
              <Text style={styles.settingDescription}>
                Automatically reconnect if connection drops
              </Text>
            </View>
            <Switch
              value={vpnStatus?.autoReconnect ?? true}
              onValueChange={handleToggleAutoReconnect}
            />
          </View>
        </Card.Content>
      </Card>

      {/* Privacy & Blocking */}
      <Card style={styles.card}>
        <Card.Title title="Privacy & Blocking" />
        <Card.Content>
          <View style={styles.settingRow}>
            <View style={styles.settingInfo}>
              <Text style={styles.settingTitle}>Ad Blocking</Text>
              <Text style={styles.settingDescription}>
                Block ads at VPN level
              </Text>
            </View>
            <Switch
              value={vpnStatus?.adBlocking ?? false}
              onValueChange={handleToggleAdBlocking}
            />
          </View>
          <Divider />
          <View style={styles.settingRow}>
            <View style={styles.settingInfo}>
              <Text style={styles.settingTitle}>Tracker Blocking</Text>
              <Text style={styles.settingDescription}>
                Block tracking scripts and cookies
              </Text>
            </View>
            <Switch
              value={vpnStatus?.trackerBlocking ?? false}
              onValueChange={handleToggleTrackerBlocking}
            />
          </View>
          <Divider />
          <View style={styles.settingRow}>
            <View style={styles.settingInfo}>
              <Text style={styles.settingTitle}>Malware Blocking</Text>
              <Text style={styles.settingDescription}>
                Block known malicious domains
              </Text>
            </View>
            <Switch
              value={vpnStatus?.malwareBlocking ?? true}
              onValueChange={handleToggleMalwareBlocking}
            />
          </View>
        </Card.Content>
      </Card>

      {/* Advanced Features */}
      <Card style={styles.card}>
        <Card.Title title="Advanced Features" />
        <Card.Content>
          <View style={styles.settingRow}>
            <View style={styles.settingInfo}>
              <Text style={styles.settingTitle}>Obfuscation</Text>
              <Text style={styles.settingDescription}>
                Hide VPN usage from ISP (server must support)
              </Text>
            </View>
            <Switch
              value={vpnStatus?.obfuscation ?? false}
              onValueChange={handleToggleObfuscation}
            />
          </View>
          <Divider />
          <View style={styles.settingRow}>
            <View style={styles.settingInfo}>
              <Text style={styles.settingTitle}>Split Tunneling</Text>
              <Text style={styles.settingDescription}>
                Exclude apps from VPN tunnel
              </Text>
            </View>
            <Switch
              value={vpnStatus?.splitTunneling ?? false}
              onValueChange={handleToggleSplitTunneling}
            />
          </View>
          <Divider />
          <View style={styles.settingRow}>
            <View style={styles.settingInfo}>
              <Text style={styles.settingTitle}>Multi-Hop</Text>
              <Text style={styles.settingDescription}>
                {vpnStatus?.multiHop 
                  ? `Active: ${vpnStatus.multiHopServers?.[0]?.name} → ${vpnStatus.multiHopServers?.[1]?.name}`
                  : 'Route through multiple servers for extra security'}
              </Text>
            </View>
            <Chip compact>{vpnStatus?.multiHop ? 'ON' : 'OFF'}</Chip>
          </View>
        </Card.Content>
      </Card>

      {/* Protocol Selection */}
      <Card style={styles.card}>
        <Card.Title title="VPN Protocol" />
        <Card.Content>
          <SegmentedButtons
            value={vpnStatus?.protocol || 'WireGuard'}
            onValueChange={handleProtocolChange}
            buttons={[
              {
                value: 'WireGuard',
                label: 'WireGuard',
                icon: 'shield-check',
              },
              {
                value: 'OpenVPN',
                label: 'OpenVPN',
                icon: 'shield-lock',
              },
            ]}
          />
          <Text style={styles.protocolDescription}>
            {vpnStatus?.protocol === 'WireGuard'
              ? 'Modern, fast, and lightweight protocol with strong encryption'
              : 'Mature, reliable protocol with proven security'}
          </Text>
        </Card.Content>
      </Card>

      {/* Encryption Info */}
      {vpnStatus?.encryption && (
        <Card style={styles.card}>
          <Card.Title title="Encryption Details" />
          <Card.Content>
            <View style={styles.encryptionRow}>
              <Text style={styles.encryptionLabel}>Protocol:</Text>
              <Text style={styles.encryptionValue}>{vpnStatus.encryption.protocol}</Text>
            </View>
            <View style={styles.encryptionRow}>
              <Text style={styles.encryptionLabel}>Cipher:</Text>
              <Text style={styles.encryptionValue}>{vpnStatus.encryption.cipher}</Text>
            </View>
            <View style={styles.encryptionRow}>
              <Text style={styles.encryptionLabel}>Authentication:</Text>
              <Text style={styles.encryptionValue}>
                {vpnStatus.encryption.authentication}
              </Text>
            </View>
            <View style={styles.encryptionRow}>
              <Text style={styles.encryptionLabel}>Key Exchange:</Text>
              <Text style={styles.encryptionValue}>
                {vpnStatus.encryption.keyExchange}
              </Text>
            </View>
            <View style={styles.encryptionRow}>
              <Text style={styles.encryptionLabel}>Perfect Forward Secrecy:</Text>
              <Text style={styles.encryptionValue}>
                {vpnStatus.encryption.perfect_forward_secrecy ? '✅ Yes' : '❌ No'}
              </Text>
            </View>
          </Card.Content>
        </Card>
      )}

      {/* DNS Leak Test */}
      <Card style={styles.card}>
        <Card.Title title="DNS Leak Test" />
        <Card.Content>
          <Text style={styles.description}>
            Check if your DNS queries are leaking outside the VPN tunnel
          </Text>
          <Button
            mode="contained"
            onPress={handleDNSLeakTest}
            loading={loading}
            disabled={loading}
            icon="test-tube"
            style={styles.button}>
            Run DNS Leak Test
          </Button>
        </Card.Content>
      </Card>
    </View>
  );

  return (
    <ScrollView
      style={[styles.container, {backgroundColor: theme.colors.background}]}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}>
      <Surface style={styles.header} elevation={2}>
        <Icon name="shield-lock" size={32} color={theme.colors.primary} />
        <Text style={styles.headerTitle}>Secure VPN</Text>
      </Surface>

      <SegmentedButtons
        value={selectedTab}
        onValueChange={setSelectedTab}
        buttons={[
          {value: 'status', label: 'Status', icon: 'shield-check'},
          {value: 'settings', label: 'Settings', icon: 'cog'},
        ]}
        style={styles.tabs}
      />

      {selectedTab === 'status' ? renderStatusTab() : renderSettingsTab()}
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 16,
    gap: 12,
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: 'bold',
  },
  tabs: {
    margin: 16,
  },
  card: {
    margin: 16,
    marginBottom: 8,
  },
  statusContainer: {
    alignItems: 'center',
    marginVertical: 20,
  },
  statusText: {
    fontSize: 24,
    fontWeight: 'bold',
    marginTop: 16,
  },
  serverText: {
    fontSize: 16,
    marginTop: 8,
    opacity: 0.7,
  },
  button: {
    marginTop: 12,
  },
  statRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 8,
    gap: 12,
  },
  statLabel: {
    flex: 1,
    fontSize: 16,
  },
  statValue: {
    fontSize: 16,
    fontWeight: 'bold',
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginTop: 8,
    marginBottom: 12,
  },
  serverItem: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 12,
    borderRadius: 8,
    marginBottom: 8,
    gap: 12,
  },
  serverFlag: {
    fontSize: 32,
  },
  serverInfo: {
    flex: 1,
  },
  serverName: {
    fontSize: 16,
    fontWeight: 'bold',
  },
  serverDetails: {
    fontSize: 12,
    opacity: 0.7,
    marginTop: 2,
  },
  featureChips: {
    flexDirection: 'row',
    gap: 4,
    marginTop: 4,
    flexWrap: 'wrap',
  },
  featureChip: {
    height: 24,
  },
  serverActions: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
  },
  divider: {
    marginVertical: 12,
  },
  settingRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 12,
  },
  settingInfo: {
    flex: 1,
  },
  settingTitle: {
    fontSize: 16,
    fontWeight: 'bold',
  },
  settingDescription: {
    fontSize: 12,
    opacity: 0.7,
    marginTop: 2,
  },
  protocolDescription: {
    fontSize: 12,
    opacity: 0.7,
    marginTop: 12,
    textAlign: 'center',
  },
  encryptionRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 6,
  },
  encryptionLabel: {
    fontSize: 14,
    opacity: 0.7,
  },
  encryptionValue: {
    fontSize: 14,
    fontWeight: 'bold',
  },
  description: {
    fontSize: 14,
    opacity: 0.7,
    marginBottom: 12,
  },
  blockedStatRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 8,
    gap: 16,
  },
  blockedStatInfo: {
    flex: 1,
  },
  blockedStatLabel: {
    fontSize: 14,
    opacity: 0.7,
  },
  blockedStatValue: {
    fontSize: 20,
    fontWeight: 'bold',
    marginTop: 4,
  },
  speedTestResults: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginBottom: 16,
  },
  speedMetric: {
    alignItems: 'center',
    gap: 4,
  },
  speedLabel: {
    fontSize: 12,
    opacity: 0.7,
  },
  speedValue: {
    fontSize: 16,
    fontWeight: 'bold',
  },
});

export default VPNScreen;
