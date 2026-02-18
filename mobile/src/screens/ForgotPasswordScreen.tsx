import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  KeyboardAvoidingView,
  Platform,
  Alert,
} from 'react-native';
import { TextInput, Button, HelperText } from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import { AuthService } from '../services/AuthService';

interface ForgotPasswordScreenProps {
  navigation: any;
}

const ForgotPasswordScreen = ({ navigation }: ForgotPasswordScreenProps): JSX.Element => {
  const [email, setEmail] = useState('');
  const [resetCode, setResetCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [step, setStep] = useState<'email' | 'code' | 'password'>('email');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState({
    email: '',
    code: '',
    password: '',
    confirmPassword: '',
  });

  const validateEmail = (email: string) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const handleRequestReset = async () => {
    if (!email) {
      setErrors({ ...errors, email: 'Email is required' });
      return;
    }
    if (!validateEmail(email)) {
      setErrors({ ...errors, email: 'Invalid email format' });
      return;
    }

    setLoading(true);
    try {
      const result = await AuthService.requestPasswordReset(email);
      if (result.success) {
        Alert.alert('Success', 'Reset code sent to your email!');
        setStep('code');
        setErrors({ email: '', code: '', password: '', confirmPassword: '' });
      } else {
        Alert.alert('Error', result.error || 'Failed to send reset code');
      }
    } catch (error) {
      Alert.alert('Error', 'An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyCode = async () => {
    if (!resetCode) {
      setErrors({ ...errors, code: 'Reset code is required' });
      return;
    }
    if (resetCode.length !== 6) {
      setErrors({ ...errors, code: 'Reset code must be 6 digits' });
      return;
    }

    setLoading(true);
    try {
      const result = await AuthService.verifyResetCode(email, resetCode);
      if (result.success) {
        setStep('password');
        setErrors({ email: '', code: '', password: '', confirmPassword: '' });
      } else {
        Alert.alert('Error', result.error || 'Invalid reset code');
      }
    } catch (error) {
      Alert.alert('Error', 'An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async () => {
    const newErrors = { email: '', code: '', password: '', confirmPassword: '' };

    if (!newPassword) {
      newErrors.password = 'Password is required';
    } else if (newPassword.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }

    if (!confirmPassword) {
      newErrors.confirmPassword = 'Please confirm your password';
    } else if (newPassword !== confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    if (newErrors.password || newErrors.confirmPassword) {
      setErrors(newErrors);
      return;
    }

    setLoading(true);
    try {
      const result = await AuthService.resetPassword(email, resetCode, newPassword);
      if (result.success) {
        Alert.alert(
          'Success',
          'Password reset successfully! Please login with your new password.',
          [{ text: 'OK', onPress: () => navigation.goBack() }]
        );
      } else {
        Alert.alert('Error', result.error || 'Failed to reset password');
      }
    } catch (error) {
      Alert.alert('Error', 'An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <View style={styles.header}>
          <Icon name="lock-reset" size={80} color="#2196f3" />
          <Text style={styles.title}>Reset Password</Text>
          <Text style={styles.subtitle}>
            {step === 'email' && 'Enter your email to receive a reset code'}
            {step === 'code' && 'Enter the 6-digit code sent to your email'}
            {step === 'password' && 'Create a new password'}
          </Text>
        </View>

        <View style={styles.form}>
          {step === 'email' && (
            <>
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

              <Button
                mode="contained"
                onPress={handleRequestReset}
                loading={loading}
                disabled={loading}
                style={styles.button}
                icon="send">
                Send Reset Code
              </Button>
            </>
          )}

          {step === 'code' && (
            <>
              <TextInput
                label="Reset Code"
                value={resetCode}
                onChangeText={setResetCode}
                mode="outlined"
                keyboardType="number-pad"
                maxLength={6}
                left={<TextInput.Icon icon="shield-key" />}
                error={!!errors.code}
                style={styles.input}
              />
              <HelperText type="error" visible={!!errors.code}>
                {errors.code}
              </HelperText>

              <Button
                mode="contained"
                onPress={handleVerifyCode}
                loading={loading}
                disabled={loading}
                style={styles.button}
                icon="check">
                Verify Code
              </Button>

              <Button
                mode="text"
                onPress={handleRequestReset}
                disabled={loading}
                style={styles.textButton}>
                Resend Code
              </Button>
            </>
          )}

          {step === 'password' && (
            <>
              <TextInput
                label="New Password"
                value={newPassword}
                onChangeText={setNewPassword}
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

              <Button
                mode="contained"
                onPress={handleResetPassword}
                loading={loading}
                disabled={loading}
                style={styles.button}
                icon="key">
                Reset Password
              </Button>
            </>
          )}

          <Button
            mode="text"
            onPress={() => navigation.goBack()}
            disabled={loading}
            style={styles.textButton}>
            Back to Login
          </Button>
        </View>

        <View style={styles.infoBox}>
          <Icon name="information" size={20} color="#2196f3" />
          <Text style={styles.infoText}>
            {step === 'email' && 'You will receive a 6-digit code via email'}
            {step === 'code' && 'Check your email for the reset code'}
            {step === 'password' && 'Choose a strong password with at least 6 characters'}
          </Text>
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
  form: {
    marginBottom: 24,
  },
  input: {
    marginBottom: 4,
  },
  button: {
    marginTop: 16,
    paddingVertical: 8,
  },
  textButton: {
    marginTop: 8,
  },
  infoBox: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#e3f2fd',
    padding: 16,
    borderRadius: 8,
    gap: 12,
  },
  infoText: {
    flex: 1,
    fontSize: 13,
    color: '#1976d2',
  },
});

export default ForgotPasswordScreen;
