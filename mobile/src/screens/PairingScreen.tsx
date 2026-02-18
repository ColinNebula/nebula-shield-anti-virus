import React, {useState, useEffect} from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Alert,
  Platform,
} from 'react-native';
import {TextInput, Button, Card, Chip} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import QRCode from 'react-native-qrcode-svg';
// import {SocketService} from '../services/SocketService'; // Disabled - using HTTP API

interface PairingScreenProps {
  navigation: any;
  onPairingSuccess: () => void;
}

const PairingScreen = ({navigation, onPairingSuccess}: PairingScreenProps): JSX.Element => {
  const [pairingCode, setPairingCode] = useState('');
  const [generatedCode, setGeneratedCode] = useState('');
  const [qrData, setQrData] = useState('');
  const [isPairing, setIsPairing] = useState(false);
  const [pairedDevices, setPairedDevices] = useState<any[]>([]);
  const [step, setStep] = useState<'input' | 'qr' | 'success'>('input');

  useEffect(() => {
    // WebSocket disabled - using HTTP API
    // SocketService.on('pairing:success', (data) => {
    //   setIsPairing(false);
    //   setStep('success');
    //   setPairedDevices((prev) => [...prev, data.device]);
    //   Alert.alert('Success', `Paired with ${data.device.name || 'Desktop'}`);
    //   setTimeout(() => {
    //     onPairingSuccess();
    //   }, 2000);
    // });

    // SocketService.on('pairing:failed', (data) => {
    //   setIsPairing(false);
    //   Alert.alert('Pairing Failed', data.message || 'Invalid pairing code');
    // });

    // SocketService.on('devices:list', (data) => {
    //   if (Array.isArray(data)) {
    //     setPairedDevices(data);
    //   }
    // });

    // SocketService.emit('request:devices', {});

    return () => {
      // SocketService.off('pairing:success');
      // SocketService.off('pairing:failed');
      // SocketService.off('devices:list');
    };
  }, []);

  const handleGenerateQR = () => {
    // Generate a unique pairing code
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();
    setGeneratedCode(code);
    
    // Create QR data with device info
    const qrPayload = {
      code: code,
      type: 'mobile',
      platform: Platform.OS,
      timestamp: Date.now(),
    };
    setQrData(JSON.stringify(qrPayload));
    setStep('qr');

    // Notify backend to expect this pairing code
    // SocketService.emit('pairing:generate', {code});
  };

  const handleManualPairing = () => {
    if (!pairingCode || pairingCode.length < 6) {
      Alert.alert('Invalid Code', 'Please enter a valid pairing code');
      return;
    }

    setIsPairing(true);
    // SocketService.emit('pairing:request', {
    //   code: pairingCode.toUpperCase(),
    //   deviceType: 'mobile',
    //   platform: Platform.OS,
    // });
    Alert.alert('Feature Disabled', 'Pairing requires WebSocket support');
    setIsPairing(false);
  };

  const handleSkip = () => {
    Alert.alert(
      'Skip Pairing?',
      'You can pair your device later from the Settings screen.',
      [
        {text: 'Cancel', style: 'cancel'},
        {text: 'Skip', onPress: () => onPairingSuccess()},
      ]
    );
  };

  if (step === 'success') {
    return (
      <View style={styles.container}>
        <View style={styles.successContainer}>
          <Icon name="check-circle" size={100} color="#4caf50" />
          <Text style={styles.successTitle}>Pairing Successful!</Text>
          <Text style={styles.successSubtitle}>
            Your mobile device is now connected
          </Text>
          <Button
            mode="contained"
            onPress={onPairingSuccess}
            style={styles.doneButton}>
            Get Started
          </Button>
        </View>
      </View>
    );
  }

  if (step === 'qr') {
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.scrollContent}>
        <View style={styles.header}>
          <Icon name="qrcode-scan" size={60} color="#2196f3" />
          <Text style={styles.title}>Scan QR Code</Text>
          <Text style={styles.subtitle}>
            Scan this code from your desktop application
          </Text>
        </View>

        <Card style={styles.qrCard}>
          <Card.Content style={styles.qrCardContent}>
            <View style={styles.qrWrapper}>
              <QRCode value={qrData} size={200} />
            </View>
            <Text style={styles.qrCode}>{generatedCode}</Text>
            <Text style={styles.qrInstructions}>
              Open Nebula Shield on your desktop and click "Pair Mobile Device"
            </Text>
          </Card.Content>
        </Card>

        <View style={styles.buttonGroup}>
          <Button
            mode="outlined"
            onPress={() => setStep('input')}
            style={styles.backButton}>
            Back
          </Button>
          <Button mode="text" onPress={handleGenerateQR}>
            Regenerate Code
          </Button>
        </View>
      </ScrollView>
    );
  }

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.scrollContent}>
      <View style={styles.header}>
        <Icon name="information" size={60} color="#00a8ff" />
        <Text style={styles.title}>Pairing Not Required</Text>
        <Text style={styles.subtitle}>
          Your mobile app is already connected via HTTP API
        </Text>
      </View>

      <Card style={styles.card}>
        <Card.Content>
          <Text style={{fontSize: 16, marginBottom: 12, fontWeight: 'bold'}}>✓ Already Connected</Text>
          <Text style={{fontSize: 14, color: '#666', marginBottom: 8}}>
            Backend URL: http://10.0.0.72:8080/api
          </Text>
          <Text style={{fontSize: 14, color: '#666', marginBottom: 16}}>
            Your mobile app can access all features without pairing.
          </Text>
          
          <Text style={{fontSize: 16, marginBottom: 12, marginTop: 16, fontWeight: 'bold'}}>Available Features:</Text>
          <Text style={{fontSize: 14, color: '#666'}}>• Dashboard with system metrics</Text>
          <Text style={{fontSize: 14, color: '#666'}}>• Quick and Full scans</Text>
          <Text style={{fontSize: 14, color: '#666'}}>• Virus signature updates</Text>
          <Text style={{fontSize: 14, color: '#666'}}>• Real-time monitoring</Text>
          
          <Text style={{fontSize: 12, color: '#999', marginTop: 20, fontStyle: 'italic'}}>
            Note: QR code pairing requires WebSocket support (currently disabled)
          </Text>
        </Card.Content>
      </Card>
    </ScrollView>
  );
};

/* Original pairing code - disabled
  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.scrollContent}>
      <View style={styles.header}>
        <Icon name="cellphone-link" size={60} color="#2196f3" />
        <Text style={styles.title}>Pair Your Device</Text>
        <Text style={styles.subtitle}>
          Connect your mobile to your desktop for remote monitoring
        </Text>
      </View>

      <Card style={styles.card}>
        <Card.Title
          title="Method 1: QR Code"
          left={(props) => <Icon name="qrcode" {...props} size={24} color="#2196f3" />}
        />
        <Card.Content>
          <Text style={styles.methodDescription}>
            Generate a QR code and scan it from your desktop application
          </Text>
          <Button
            mode="contained"
            icon="qrcode-scan"
            onPress={handleGenerateQR}
            style={styles.methodButton}>
            Generate QR Code
          </Button>
        </Card.Content>
      </Card>

      <View style={styles.divider}>
        <View style={styles.dividerLine} />
        <Text style={styles.dividerText}>OR</Text>
        <View style={styles.dividerLine} />
      </View>

      <Card style={styles.card}>
        <Card.Title
          title="Method 2: Pairing Code"
          left={(props) => <Icon name="form-textbox" {...props} size={24} color="#2196f3" />}
        />
        <Card.Content>
          <Text style={styles.methodDescription}>
            Enter the pairing code shown on your desktop application
          </Text>
          <TextInput
            label="Pairing Code"
            value={pairingCode}
            onChangeText={setPairingCode}
            mode="outlined"
            autoCapitalize="characters"
            maxLength={10}
            placeholder="XXXX-XXXX"
            left={<TextInput.Icon icon="key" />}
            style={styles.input}
          />
          <Button
            mode="contained"
            icon="link"
            onPress={handleManualPairing}
            loading={isPairing}
            disabled={isPairing || !pairingCode}
            style={styles.methodButton}>
            Pair Device
          </Button>
        </Card.Content>
      </Card>

      {pairedDevices.length > 0 && (
        <Card style={styles.card}>
          <Card.Title title="Paired Devices" />
          <Card.Content>
            {pairedDevices.map((device, index) => (
              <Chip
                key={index}
                icon="laptop"
                mode="flat"
                style={styles.deviceChip}>
                {device.name || `Desktop ${index + 1}`}
              </Chip>
            ))}
          </Card.Content>
        </Card>
      )}

      <Button mode="text" onPress={handleSkip} style={styles.skipButton}>
        Skip for Now
      </Button>

      <View style={styles.instructions}>
        <Text style={styles.instructionsTitle}>How to Pair:</Text>
        <View style={styles.instructionItem}>
          <Icon name="numeric-1-circle" size={24} color="#666" />
          <Text style={styles.instructionText}>
            Open Nebula Shield on your desktop computer
          </Text>
        </View>
        <View style={styles.instructionItem}>
          <Icon name="numeric-2-circle" size={24} color="#666" />
          <Text style={styles.instructionText}>
            Click on "Mobile App" or "Pair Device" in settings
          </Text>
        </View>
        <View style={styles.instructionItem}>
          <Icon name="numeric-3-circle" size={24} color="#666" />
          <Text style={styles.instructionText}>
            Use QR code or enter the pairing code displayed
          </Text>
        </View>
      </View>
    </ScrollView>
  );
};
*/

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  scrollContent: {
    padding: 20,
  },
  header: {
    alignItems: 'center',
    marginTop: 20,
    marginBottom: 32,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#333',
    marginTop: 16,
  },
  subtitle: {
    fontSize: 14,
    color: '#666',
    marginTop: 8,
    textAlign: 'center',
    paddingHorizontal: 20,
  },
  card: {
    marginBottom: 16,
  },
  methodDescription: {
    fontSize: 14,
    color: '#666',
    marginBottom: 16,
  },
  methodButton: {
    marginTop: 8,
  },
  divider: {
    flexDirection: 'row',
    alignItems: 'center',
    marginVertical: 24,
  },
  dividerLine: {
    flex: 1,
    height: 1,
    backgroundColor: '#e0e0e0',
  },
  dividerText: {
    marginHorizontal: 16,
    fontSize: 14,
    color: '#999',
    fontWeight: '600',
  },
  input: {
    marginBottom: 8,
  },
  deviceChip: {
    marginRight: 8,
    marginBottom: 8,
  },
  skipButton: {
    marginTop: 16,
  },
  instructions: {
    marginTop: 32,
    padding: 16,
    backgroundColor: '#fff',
    borderRadius: 8,
  },
  instructionsTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 16,
  },
  instructionItem: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 12,
    gap: 12,
  },
  instructionText: {
    flex: 1,
    fontSize: 14,
    color: '#666',
  },
  qrCard: {
    marginVertical: 24,
  },
  qrCardContent: {
    alignItems: 'center',
    padding: 24,
  },
  qrWrapper: {
    padding: 20,
    backgroundColor: '#fff',
    borderRadius: 12,
    borderWidth: 2,
    borderColor: '#2196f3',
  },
  qrCode: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#333',
    marginTop: 16,
    letterSpacing: 2,
  },
  qrInstructions: {
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
    marginTop: 8,
  },
  buttonGroup: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  backButton: {
    flex: 1,
    marginRight: 8,
  },
  successContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 40,
  },
  successTitle: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#333',
    marginTop: 24,
  },
  successSubtitle: {
    fontSize: 16,
    color: '#666',
    marginTop: 8,
    textAlign: 'center',
  },
  doneButton: {
    marginTop: 32,
    paddingHorizontal: 32,
  },
});

export default PairingScreen;
