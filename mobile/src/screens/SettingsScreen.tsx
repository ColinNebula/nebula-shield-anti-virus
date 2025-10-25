import React from 'react';
import {View, Text, StyleSheet, ScrollView} from 'react-native';
import {Card, Switch, Button, List} from 'react-native-paper';

const SettingsScreen = (): JSX.Element => {
  const [notifications, setNotifications] = React.useState(true);
  const [autoUpdate, setAutoUpdate] = React.useState(true);
  const [biometric, setBiometric] = React.useState(false);

  return (
    <ScrollView style={styles.container}>
      <Card style={styles.card}>
        <Card.Title title="Notifications" />
        <Card.Content>
          <List.Item
            title="Threat Alerts"
            description="Receive alerts when threats are detected"
            right={() => (
              <Switch 
                value={notifications} 
                onValueChange={setNotifications} 
              />
            )}
          />
          <List.Item
            title="Scan Completion"
            description="Notify when scans complete"
            right={() => (
              <Switch value={autoUpdate} onValueChange={setAutoUpdate} />
            )}
          />
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Security" />
        <Card.Content>
          <List.Item
            title="Biometric Login"
            description="Use Face ID or fingerprint to unlock"
            right={() => (
              <Switch value={biometric} onValueChange={setBiometric} />
            )}
          />
        </Card.Content>
      </Card>

      <Card style={styles.card}>
        <Card.Title title="Account" />
        <Card.Content>
          <Button mode="outlined" style={styles.button}>
            Manage Subscription
          </Button>
          <Button mode="outlined" style={styles.button}>
            Privacy Policy
          </Button>
          <Button mode="text" textColor="#f44336" style={styles.button}>
            Logout
          </Button>
        </Card.Content>
      </Card>

      <Text style={styles.version}>Nebula Shield Mobile v1.0.0</Text>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  card: {
    margin: 16,
    marginBottom: 0,
  },
  button: {
    marginTop: 12,
  },
  version: {
    textAlign: 'center',
    color: '#999',
    fontSize: 12,
    padding: 32,
  },
});

export default SettingsScreen;
