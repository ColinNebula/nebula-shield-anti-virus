import React, {useState} from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  KeyboardAvoidingView,
  Platform,
  Image,
  Alert,
} from 'react-native';
import {TextInput, Button, HelperText} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import {AuthService} from '../services/AuthService';

interface LoginScreenProps {
  navigation: any;
  onLoginSuccess: () => void;
}

const LoginScreen = ({navigation, onLoginSuccess}: LoginScreenProps): JSX.Element => {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    fullName: '',
  });

  const validateEmail = (email: string) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const validateForm = () => {
    const newErrors = {
      email: '',
      password: '',
      confirmPassword: '',
      fullName: '',
    };

    if (!email) {
      newErrors.email = 'Email is required';
    } else if (!validateEmail(email)) {
      newErrors.email = 'Invalid email format';
    }

    if (!password) {
      newErrors.password = 'Password is required';
    } else if (password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }

    if (!isLogin) {
      if (!fullName) {
        newErrors.fullName = 'Full name is required';
      }
      if (!confirmPassword) {
        newErrors.confirmPassword = 'Please confirm your password';
      } else if (password !== confirmPassword) {
        newErrors.confirmPassword = 'Passwords do not match';
      }
    }

    setErrors(newErrors);
    return !Object.values(newErrors).some((error) => error !== '');
  };

  const handleLogin = async () => {
    if (!validateForm()) return;

    setLoading(true);
    try {
      const result = await AuthService.login(email, password);
      if (result.success) {
        Alert.alert('Success', 'Logged in successfully!');
        onLoginSuccess();
      } else {
        Alert.alert('Login Failed', result.error || 'Invalid credentials');
      }
    } catch (error) {
      Alert.alert('Error', 'An error occurred during login');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
    if (!validateForm()) return;

    setLoading(true);
    try {
      const result = await AuthService.register(email, password, fullName);
      if (result.success) {
        Alert.alert('Success', 'Account created successfully!');
        onLoginSuccess();
      } else {
        Alert.alert('Registration Failed', result.error || 'Could not create account');
      }
    } catch (error) {
      Alert.alert('Error', 'An error occurred during registration');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = () => {
    if (isLogin) {
      handleLogin();
    } else {
      handleRegister();
    }
  };

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView
        contentContainerStyle={styles.scrollContent}
        keyboardShouldPersistTaps="handled">
        <View style={styles.header}>
          <Icon name="shield-lock" size={80} color="#2196f3" />
          <Text style={styles.title}>Nebula Shield</Text>
          <Text style={styles.subtitle}>Mobile Companion</Text>
        </View>

        <View style={styles.formContainer}>
          <View style={styles.tabContainer}>
            <Button
              mode={isLogin ? 'contained' : 'text'}
              onPress={() => setIsLogin(true)}
              style={[styles.tab, isLogin && styles.activeTab]}
              labelStyle={[styles.tabLabel, isLogin && styles.activeTabLabel]}>
              Login
            </Button>
            <Button
              mode={!isLogin ? 'contained' : 'text'}
              onPress={() => setIsLogin(false)}
              style={[styles.tab, !isLogin && styles.activeTab]}
              labelStyle={[styles.tabLabel, !isLogin && styles.activeTabLabel]}>
              Register
            </Button>
          </View>

          <View style={styles.form}>
            {!isLogin && (
              <>
                <TextInput
                  label="Full Name"
                  value={fullName}
                  onChangeText={setFullName}
                  mode="outlined"
                  left={<TextInput.Icon icon="account" />}
                  error={!!errors.fullName}
                  style={styles.input}
                />
                <HelperText type="error" visible={!!errors.fullName}>
                  {errors.fullName}
                </HelperText>
              </>
            )}

            <TextInput
              label="Email"
              value={email}
              onChangeText={setEmail}
              mode="outlined"
              keyboardType="email-address"
              autoCapitalize="none"
              left={<TextInput.Icon icon="email" />}
              error={!!errors.email}
              style={styles.input}
            />
            <HelperText type="error" visible={!!errors.email}>
              {errors.email}
            </HelperText>

            <TextInput
              label="Password"
              value={password}
              onChangeText={setPassword}
              mode="outlined"
              secureTextEntry={!showPassword}
              left={<TextInput.Icon icon="lock" />}
              right={
                <TextInput.Icon
                  icon={showPassword ? 'eye-off' : 'eye'}
                  onPress={() => setShowPassword(!showPassword)}
                />
              }
              error={!!errors.password}
              style={styles.input}
            />
            <HelperText type="error" visible={!!errors.password}>
              {errors.password}
            </HelperText>

            {!isLogin && (
              <>
                <TextInput
                  label="Confirm Password"
                  value={confirmPassword}
                  onChangeText={setConfirmPassword}
                  mode="outlined"
                  secureTextEntry={!showPassword}
                  left={<TextInput.Icon icon="lock-check" />}
                  error={!!errors.confirmPassword}
                  style={styles.input}
                />
                <HelperText type="error" visible={!!errors.confirmPassword}>
                  {errors.confirmPassword}
                </HelperText>
              </>
            )}

            <Button
              mode="contained"
              onPress={handleSubmit}
              loading={loading}
              disabled={loading}
              style={styles.submitButton}
              icon={isLogin ? 'login' : 'account-plus'}>
              {isLogin ? 'Login' : 'Create Account'}
            </Button>

            {isLogin && (
              <Button
                mode="text"
                onPress={() => navigation.navigate('ForgotPassword')}
                style={styles.forgotButton}>
                Forgot Password?
              </Button>
            )}
          </View>

          <View style={styles.features}>
            <View style={styles.feature}>
              <Icon name="shield-check" size={24} color="#4caf50" />
              <Text style={styles.featureText}>Real-time Protection</Text>
            </View>
            <View style={styles.feature}>
              <Icon name="cloud-sync" size={24} color="#2196f3" />
              <Text style={styles.featureText}>Cloud Sync</Text>
            </View>
            <View style={styles.feature}>
              <Icon name="bell-alert" size={24} color="#ff9800" />
              <Text style={styles.featureText}>Instant Alerts</Text>
            </View>
          </View>
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  scrollContent: {
    flexGrow: 1,
    padding: 20,
  },
  header: {
    alignItems: 'center',
    marginTop: 40,
    marginBottom: 32,
  },
  title: {
    fontSize: 32,
    fontWeight: 'bold',
    color: '#333',
    marginTop: 16,
  },
  subtitle: {
    fontSize: 16,
    color: '#666',
    marginTop: 4,
  },
  formContainer: {
    flex: 1,
  },
  tabContainer: {
    flexDirection: 'row',
    marginBottom: 24,
    gap: 12,
  },
  tab: {
    flex: 1,
    borderRadius: 8,
  },
  activeTab: {
    backgroundColor: '#2196f3',
  },
  tabLabel: {
    fontSize: 16,
    fontWeight: '600',
  },
  activeTabLabel: {
    color: '#fff',
  },
  form: {
    marginBottom: 32,
  },
  input: {
    marginBottom: 4,
  },
  submitButton: {
    marginTop: 16,
    paddingVertical: 8,
  },
  forgotButton: {
    marginTop: 8,
  },
  features: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    paddingVertical: 24,
    borderTopWidth: 1,
    borderTopColor: '#e0e0e0',
  },
  feature: {
    alignItems: 'center',
    gap: 8,
  },
  featureText: {
    fontSize: 12,
    color: '#666',
    textAlign: 'center',
  },
});

export default LoginScreen;
