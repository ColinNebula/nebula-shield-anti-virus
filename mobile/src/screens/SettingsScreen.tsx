import React, {useEffect} from 'react';
import {View, Text, StyleSheet, ScrollView, Alert, TouchableOpacity} from 'react-native';
import {Card, Switch, Button, List, Snackbar, Divider, RadioButton, useTheme as usePaperTheme} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import {useNavigation} from '@react-navigation/native';
import type {BottomTabNavigationProp} from '@react-navigation/bottom-tabs';
import AsyncStorage from '@react-native-async-storage/async-storage';
import ApiService from '../services/ApiService';
import {useTheme as useAppTheme} from '../context/ThemeContext';

type TabParamList = {
  Dashboard: undefined;
  Scans: undefined;
  Tools: undefined;
  Network: undefined;
  Settings: undefined;
};

type NavigationProp = BottomTabNavigationProp<TabParamList>;

const SettingsScreen = (): JSX.Element => {
  const navigation = useNavigation<NavigationProp>();
  const {themeMode, setThemeMode} = useAppTheme();
  const paperTheme = usePaperTheme();
  const [notifications, setNotifications] = React.useState(true);
  const [autoUpdate, setAutoUpdate] = React.useState(true);
  const [biometric, setBiometric] = React.useState(false);
  const [realTimeProtection, setRealTimeProtection] = React.useState(true);
  const [webShield, setWebShield] = React.useState(true);
  const [updating, setUpdating] = React.useState(false);
  const [snackbarVisible, setSnackbarVisible] = React.useState(false);
  const [snackbarMessage, setSnackbarMessage] = React.useState('');
  const [subscription, setSubscription] = React.useState<any>(null);
  const [loadingSubscription, setLoadingSubscription] = React.useState(false);

  // Load settings on mount
  useEffect(() => {
    loadSettings();
    loadSubscriptionInfo();
  }, []);

  const loadSettings = async () => {
    try {
      const savedNotifications = await AsyncStorage.getItem('settings_notifications');
      const savedAutoUpdate = await AsyncStorage.getItem('settings_autoUpdate');
      const savedBiometric = await AsyncStorage.getItem('settings_biometric');
      const savedRealTimeProtection = await AsyncStorage.getItem('settings_realTimeProtection');
      const savedWebShield = await AsyncStorage.getItem('web_shield_enabled');

      if (savedNotifications !== null) setNotifications(savedNotifications === 'true');
      if (savedAutoUpdate !== null) setAutoUpdate(savedAutoUpdate === 'true');
      if (savedBiometric !== null) setBiometric(savedBiometric === 'true');
      if (savedRealTimeProtection !== null) setRealTimeProtection(savedRealTimeProtection === 'true');
      if (savedWebShield !== null) setWebShield(savedWebShield === 'true');
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  };

  const saveSettings = async (key: string, value: boolean) => {
    try {
      await AsyncStorage.setItem(key, value.toString());
    } catch (error) {
      console.error('Failed to save setting:', error);
    }
  };

  const handleNotificationsChange = (value: boolean) => {
    setNotifications(value);
    saveSettings('settings_notifications', value);
  };

  const handleAutoUpdateChange = (value: boolean) => {
    setAutoUpdate(value);
    saveSettings('settings_autoUpdate', value);
  };

  const handleBiometricChange = (value: boolean) => {
    setBiometric(value);
    saveSettings('settings_biometric', value);
  };

  const handleUpdateSignatures = async () => {
    setUpdating(true);
    const result = await ApiService.updateSignatures();
    setUpdating(false);
    
    if (result.success) {
      const data = result.data;
      const message = data.newSignatures 
        ? `Updated successfully!\n\n• New signatures: ${data.newSignatures}\n• Total signatures: ${data.totalSignatures.toLocaleString()}\n• Source: ${data.source || 'VirusTotal'}`
        : `Updated successfully!\n\n• Total signatures: ${data.totalSignatures.toLocaleString()}\n• Source: ${data.source || 'VirusTotal'}\n• Engines: ${data.engines || 'N/A'}`;
      
      Alert.alert('✅ Signatures Updated', message, [{text: 'OK'}]);
    } else {
      Alert.alert('Update Failed', result.error || 'Failed to update virus signatures');
    }
  };

  const loadSubscriptionInfo = async () => {
    setLoadingSubscription(true);
    try {
      const response = await ApiService.client.get('/subscription');
      if (response.data.success) {
        setSubscription(response.data.subscription);
      }
    } catch (error: any) {
      console.error('Failed to load subscription:', error);
      // Silently fail - subscription is optional info
      if (error?.code === 'ERR_NETWORK' || error?.message?.includes('Network')) {
        console.log('Network error loading subscription - will retry later');
      }
    }
    setLoadingSubscription(false);
  };

  const handleManageSubscription = async () => {
    if (loadingSubscription) {
      setSnackbarMessage('Loading subscription info...');
      setSnackbarVisible(true);
      return;
    }

    const tier = subscription?.tier || 'free';
    const status = subscription?.status || 'active';
    const expiresAt = subscription?.expires_at 
      ? new Date(subscription.expires_at).toLocaleDateString()
      : 'N/A';

    const tierName = tier === 'premium' ? 'Premium' : tier === 'business' ? 'Business' : 'Free';
    const tierEmoji = tier === 'premium' ? '👑' : tier === 'business' ? '💼' : '🆓';

    Alert.alert(
      `${tierEmoji} Current Plan: ${tierName}`,
      `Status: ${status.charAt(0).toUpperCase() + status.slice(1)}\n${tier !== 'free' ? `Expires: ${expiresAt}\n` : ''}
${tier === 'free' 
  ? '• Real-time Protection\n• Basic Scans\n• Limited VPN\n• Web Shield\n\nUpgrade for:\n• Unlimited VPN\n• Advanced Scans\n• Priority Support\n• Ad Blocking' 
  : tier === 'premium'
  ? '• All Free features\n• Unlimited VPN\n• Advanced Scans\n• Priority Support\n• Ad Blocking\n• 10 Devices'
  : '• All Premium features\n• 50 Devices\n• Dedicated Support\n• Custom Security\n• Team Management'}`,
      [
        {text: 'Close', style: 'cancel'},
        ...(tier === 'free' ? [{
          text: 'Upgrade to Premium',
          onPress: () => handleUpgradeSubscription('premium')
        }] : []),
        ...(tier === 'premium' ? [{
          text: 'Upgrade to Business',
          onPress: () => handleUpgradeSubscription('business')
        }] : []),
      ]
    );
  };

  const handleUpgradeSubscription = async (newTier: string) => {
    Alert.alert(
      `Upgrade to ${newTier === 'premium' ? 'Premium' : 'Business'}`,
      `${newTier === 'premium' 
        ? '💎 Premium Plan - $9.99/month\n\n• Unlimited VPN\n• Advanced Scans\n• Priority Support\n• Ad Blocking\n• 10 Devices' 
        : '💼 Business Plan - $29.99/month\n\n• All Premium features\n• 50 Devices\n• Dedicated Support\n• Custom Security\n• Team Management'}\n\nProceed to payment?`,
      [
        {text: 'Cancel', style: 'cancel'},
        {
          text: 'Continue',
          onPress: async () => {
            try {
              const response = await ApiService.client.post('/subscription/upgrade', {
                tier: newTier
              });
              
              if (response.data.success) {
                setSubscription(response.data.subscription);
                Alert.alert(
                  '✅ Upgrade Successful!',
                  `You are now on the ${newTier === 'premium' ? 'Premium' : 'Business'} plan.\n\nEnjoy your enhanced features!`,
                  [{text: 'OK'}]
                );
              } else {
                Alert.alert('Upgrade Failed', response.data.message || 'Please try again');
              }
            } catch (error: any) {
              Alert.alert('Error', error.message || 'Failed to upgrade subscription');
            }
          }
        }
      ]
    );
  };

  return (
    <ScrollView style={[styles.container, {backgroundColor: paperTheme.colors.background}]}>
      <Card style={styles.card}>
        <Card.Title title="Protection" />
        <Card.Content>
          <List.Item
            title="Real-time Protection"
            description="Continuously monitor for threats"
            left={props => <Icon name="shield-check" size={24} color="#4caf50" {...props} />}
            right={() => (
              <Switch
                value={realTimeProtection}
                onValueChange={(value) => {
                  setRealTimeProtection(value);
                  saveSettings('settings_realTimeProtection', value);
                }}
              />
            )}
          />
          <Divider />
          <List.Item
            title="Web Shield"
            description="Block malicious sites and phishing"
            left={props => <Icon name="web" size={24} color="#2196f3" {...props} />}
            right={() => (
              <Switch
                value={webShield}
                onValueChange={async (value) => {
                  setWebShield(value);
                  await AsyncStorage.setItem('web_shield_enabled', value.toString());
                  setSnackbarMessage(value ? 'Web Shield enabled' : 'Web Shield disabled');
                  setSnackbarVisible(true);
                }}
              />
            )}
          />
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Notifications" />
        <Card.Content>
          <List.Item
            title="Threat Alerts"
            description="Receive alerts when threats are detected"
            right={() => (
              <Switch 
                value={notifications} 
                onValueChange={handleNotificationsChange} 
              />
            )}
          />
          <List.Item
            title="Scan Completion"
            description="Notify when scans complete"
            right={() => (
              <Switch value={autoUpdate} onValueChange={handleAutoUpdateChange} />
            )}
          />
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Security & Appearance" />
        <Card.Content>
          <List.Item
            title="Biometric Login"
            description="Use Face ID or fingerprint to unlock"
            left={props => <Icon name="fingerprint" size={24} color="#2196f3" {...props} />}
            right={() => (
              <Switch value={biometric} onValueChange={handleBiometricChange} />
            )}
          />
          <Divider />
          <View style={styles.themeSection}>
            <View style={styles.themeSectionHeader}>
              <Icon name="theme-light-dark" size={24} color="#9c27b0" />
              <View style={styles.themeSectionText}>
                <Text style={styles.themeSectionTitle}>Theme</Text>
                <Text style={styles.themeSectionDescription}>Choose your preferred theme</Text>
              </View>
            </View>
            <RadioButton.Group
              onValueChange={(value) => {
                console.log('Theme changing to:', value);
                setThemeMode(value as 'light' | 'dark' | 'auto');
                setSnackbarMessage(`Theme set to ${value}`);
                setSnackbarVisible(true);
              }}
              value={themeMode}>
              <TouchableOpacity 
                style={styles.radioOption}
                onPress={() => {
                  console.log('Setting theme to light');
                  setThemeMode('light');
                  setSnackbarMessage('Theme set to Light');
                  setSnackbarVisible(true);
                }}>
                <RadioButton value="light" />
                <Text style={styles.radioLabel}>Light</Text>
              </TouchableOpacity>
              <TouchableOpacity 
                style={styles.radioOption}
                onPress={() => {
                  console.log('Setting theme to dark');
                  setThemeMode('dark');
                  setSnackbarMessage('Theme set to Dark');
                  setSnackbarVisible(true);
                }}>
                <RadioButton value="dark" />
                <Text style={styles.radioLabel}>Dark</Text>
              </TouchableOpacity>
              <TouchableOpacity 
                style={styles.radioOption}
                onPress={() => {
                  console.log('Setting theme to auto');
                  setThemeMode('auto');
                  setSnackbarMessage('Theme set to Auto');
                  setSnackbarVisible(true);
                }}>
                <RadioButton value="auto" />
                <Text style={styles.radioLabel}>Auto (System)</Text>
              </TouchableOpacity>
            </RadioButton.Group>
          </View>
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Quick Access" />
        <Card.Content>
          <List.Item
            title="Scan History"
            description="View all security scans"
            left={props => <Icon name="shield-search" size={24} color="#2196f3" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => navigation.navigate('Scans')}
          />
          <Divider />
          <List.Item
            title="Quarantine Manager"
            description="Manage quarantined files"
            left={props => <Icon name="file-lock" size={24} color="#f44336" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => navigation.navigate('Tools')}
          />
          <Divider />
          <List.Item
            title="Disk Cleanup"
            description="Free up disk space"
            left={props => <Icon name="broom" size={24} color="#ff9800" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => navigation.navigate('Tools')}
          />
          <Divider />
          <List.Item
            title="Network Monitor"
            description="View network connections"
            left={props => <Icon name="network" size={24} color="#4caf50" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => navigation.navigate('Network')}
          />
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Virus Definitions" />
        <Card.Content>
          <Button 
            mode="contained" 
            onPress={handleUpdateSignatures}
            loading={updating}
            disabled={updating}
            icon="cloud-download"
            style={styles.button}>
            {updating ? 'Updating...' : 'Update Signatures'}
          </Button>
          <Text style={styles.helperText}>
            Last updated: Never
          </Text>
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Help & Support" />
        <Card.Content>
          <List.Item
            title="Documentation"
            description="User guides and tutorials"
            left={props => <Icon name="book-open-variant" size={24} color="#2196f3" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => {
              Alert.alert(
                '📚 Documentation',
                'Access comprehensive guides:\n\n• Getting Started Guide\n• VPN Setup & Usage\n• Security Best Practices\n• Troubleshooting Tips\n• Feature Tutorials',
                [{text: 'OK'}]
              );
            }}
          />
          <Divider />
          <List.Item
            title="Contact Support"
            description="Get help from our team"
            left={props => <Icon name="headset" size={24} color="#4caf50" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => {
              Alert.alert(
                '💬 Contact Support',
                'Email: support@nebulashield.com\nPhone: 1-800-NEBULA-1\n\nBusiness Hours:\nMon-Fri: 9 AM - 6 PM EST\nSat: 10 AM - 4 PM EST\n\nAverage Response: < 2 hours',
                [
                  {text: 'Email Support', onPress: () => console.log('Email support')},
                  {text: 'Close', style: 'cancel'}
                ]
              );
            }}
          />
          <Divider />
          <List.Item
            title="FAQ"
            description="Frequently asked questions"
            left={props => <Icon name="frequently-asked-questions" size={24} color="#ff9800" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => {
              Alert.alert(
                '❓ Frequently Asked Questions',
                '• How do I run a full scan?\n• What is real-time protection?\n• How does the VPN work?\n• How to restore quarantined files?\n• What is Web Shield?\n• How to update virus signatures?',
                [{text: 'OK'}]
              );
            }}
          />
          <Divider />
          <List.Item
            title="Report a Bug"
            description="Help us improve"
            left={props => <Icon name="bug" size={24} color="#f44336" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => {
              Alert.alert(
                '🐛 Report a Bug',
                'Help us improve Nebula Shield!\n\nPlease include:\n• Steps to reproduce\n• Expected behavior\n• Actual behavior\n• Screenshots (if applicable)\n\nEmail: bugs@nebulashield.com',
                [
                  {text: 'Send Report', onPress: () => console.log('Send bug report')},
                  {text: 'Cancel', style: 'cancel'}
                ]
              );
            }}
          />
          <Divider />
          <List.Item
            title="Feature Request"
            description="Suggest new features"
            left={props => <Icon name="lightbulb-on" size={24} color="#9c27b0" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => {
              Alert.alert(
                '💡 Feature Request',
                'We love hearing your ideas!\n\nShare your suggestions:\n• New security features\n• UI improvements\n• Performance enhancements\n• Integration requests\n\nEmail: features@nebulashield.com',
                [
                  {text: 'Submit Idea', onPress: () => console.log('Submit feature request')},
                  {text: 'Cancel', style: 'cancel'}
                ]
              );
            }}
          />
          <Divider />
          <List.Item
            title="System Diagnostics"
            description="Check system health"
            left={props => <Icon name="stethoscope" size={24} color="#00bcd4" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={async () => {
              const health = await ApiService.checkHealth();
              Alert.alert(
                '🏥 System Diagnostics',
                health.success 
                  ? `✅ All systems operational\n\n• API Server: Online\n• Database: Connected\n• Real-time Protection: ${realTimeProtection ? 'Active' : 'Inactive'}\n• Web Shield: ${webShield ? 'Active' : 'Inactive'}\n• Last Check: ${new Date().toLocaleTimeString()}`
                  : `⚠️ System Issues Detected\n\n${health.error}\n\nPlease check your connection and try again.`,
                [{text: 'OK'}]
              );
            }}
          />
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="About" />
        <Card.Content>
          <List.Item
            title="Version Information"
            description="Nebula Shield Mobile v1.0.0"
            left={props => <Icon name="information" size={24} color="#2196f3" {...props} />}
          />
          <Divider />
          <List.Item
            title="Privacy Policy"
            description="How we protect your data"
            left={props => <Icon name="shield-lock" size={24} color="#4caf50" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => {
              Alert.alert(
                '🔒 Privacy Policy',
                'Nebula Shield is committed to protecting your privacy.\n\n• No data collection without consent\n• Local processing by default\n• Encrypted communication\n• GDPR & CCPA compliant\n• No third-party tracking\n\nView full policy at:\nnebulashield.com/privacy',
                [{text: 'OK'}]
              );
            }}
          />
          <Divider />
          <List.Item
            title="Terms of Service"
            description="Usage terms and conditions"
            left={props => <Icon name="file-document" size={24} color="#ff9800" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => {
              Alert.alert(
                '📄 Terms of Service',
                'By using Nebula Shield you agree to:\n\n• Acceptable use policy\n• License agreement\n• Subscription terms\n• Liability limitations\n\nView full terms at:\nnebulashield.com/terms',
                [{text: 'OK'}]
              );
            }}
          />
          <Divider />
          <List.Item
            title="Open Source Licenses"
            description="Third-party software credits"
            left={props => <Icon name="code-tags" size={24} color="#9c27b0" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={() => {
              Alert.alert(
                '⚖️ Open Source Licenses',
                'Nebula Shield uses open source software:\n\n• React Native (MIT)\n• React Native Paper (MIT)\n• Axios (MIT)\n• Vector Icons (MIT)\n• And many more...\n\nFull list available at:\nnebulashield.com/licenses',
                [{text: 'OK'}]
              );
            }}
          />
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Account" />
        <Card.Content>
          <List.Item
            title={subscription ? `${subscription.tier === 'premium' ? '👑 Premium' : subscription.tier === 'business' ? '💼 Business' : '🆓 Free'} Plan` : 'Subscription'}
            description={subscription ? `Status: ${subscription.status}` : 'Loading...'}
            left={props => <Icon name="crown" size={24} color="#ffc107" {...props} />}
            right={props => <Icon name="chevron-right" size={24} color="#999" {...props} />}
            onPress={handleManageSubscription}
          />
          <Divider />
          <Button 
            mode="outlined" 
            style={styles.button}
            onPress={handleManageSubscription}
            loading={loadingSubscription}>
            Manage Subscription
          </Button>
          <Button 
            mode="text" 
            textColor="#f44336" 
            style={styles.button}
            onPress={() => {
              Alert.alert(
                'Logout',
                'Are you sure you want to logout?',
                [
                  {text: 'Cancel', style: 'cancel'},
                  {
                    text: 'Logout',
                    style: 'destructive',
                    onPress: async () => {
                      try {
                        // Call ApiService logout to clear token
                        await ApiService.logout();
                        
                        // Navigate to login screen and reset navigation state
                        // This forces the app to re-check authentication
                        const resetAction = {
                          index: 0,
                          routes: [{name: 'Login'}],
                        };
                        
                        // Since we're in a nested navigator, we need to navigate to root
                        // The app will automatically redirect to login when it detects no token
                        navigation.getParent()?.reset(resetAction);
                        
                        setSnackbarMessage('Logged out successfully');
                        setSnackbarVisible(true);
                      } catch (error) {
                        console.error('Logout error:', error);
                        // Even if there's an error, still try to clear local auth
                        await AsyncStorage.removeItem('auth_token');
                        setSnackbarMessage('Logged out');
                        setSnackbarVisible(true);
                      }
                    }
                  }
                ]
              );
            }}>
            Logout
          </Button>
        </Card.Content>
      </Card>

      <Text style={styles.version}>Nebula Shield Mobile v1.0.0</Text>
      <Text style={styles.copyright}>© 2025 Nebula Shield. All rights reserved.</Text>
      
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
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  card: {
    margin: 16,
    marginBottom: 0,
  },
  button: {
    marginTop: 12,
  },
  helperText: {
    fontSize: 12,
    color: '#666',
    marginTop: 8,
    marginLeft: 4,
  },
  version: {
    textAlign: 'center',
    color: '#999',
    fontSize: 12,
    padding: 32,
    paddingBottom: 8,
  },
  copyright: {
    textAlign: 'center',
    color: '#999',
    fontSize: 10,
    paddingBottom: 32,
  },
  themeSection: {
    paddingVertical: 12,
  },
  themeSectionHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 12,
  },
  themeSectionText: {
    flex: 1,
  },
  themeSectionTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#333',
  },
  themeSectionDescription: {
    fontSize: 14,
    color: '#666',
    marginTop: 2,
  },
  radioOption: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 8,
  },
  radioLabel: {
    fontSize: 16,
    color: '#333',
    marginLeft: 8,
  },
});

export default SettingsScreen;
