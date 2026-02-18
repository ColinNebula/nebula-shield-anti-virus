import AsyncStorage from '@react-native-async-storage/async-storage';
import axios from 'axios';
import Constants from 'expo-constants';

// Get API URL from app.json extra config
const API_URL = Constants.expoConfig?.extra?.apiUrl || 'http://10.0.0.72:3001/api';

console.log('🌐 Auth API URL:', API_URL);

class AuthServiceClass {
  private token: string | null = null;

  async login(email: string, password: string): Promise<{success: boolean; token?: string; error?: string}> {
    try {
      const response = await axios.post(`${API_URL}/auth/login`, {
        email,
        password,
      });

      if (response.data.success) {
        this.token = response.data.token;
        await AsyncStorage.setItem('auth_token', this.token);
        return {success: true, token: this.token};
      }

      return {success: false, error: response.data.error};
    } catch (error: any) {
      console.error('Login error:', error);
      return {success: false, error: error.message || 'Login failed'};
    }
  }

  async register(email: string, password: string, fullName: string): Promise<{success: boolean; token?: string; error?: string}> {
    try {
      const response = await axios.post(`${API_URL}/auth/register`, {
        email,
        password,
        fullName,
      });

      if (response.data.success) {
        this.token = response.data.token;
        await AsyncStorage.setItem('auth_token', this.token);
        return {success: true, token: this.token};
      }

      return {success: false, error: response.data.error};
    } catch (error: any) {
      console.error('Registration error:', error);
      return {success: false, error: error.message || 'Registration failed'};
    }
  }

  async logout(): Promise<void> {
    this.token = null;
    await AsyncStorage.removeItem('auth_token');
  }

  async getToken(): Promise<string | null> {
    if (this.token) {
      return this.token;
    }

    this.token = await AsyncStorage.getItem('auth_token');
    return this.token;
  }

  async isAuthenticated(): Promise<boolean> {
    const token = await this.getToken();
    return token !== null;
  }

  async requestPasswordReset(email: string): Promise<{success: boolean; error?: string}> {
    try {
      const response = await axios.post(`${API_URL}/auth/forgot-password`, {
        email,
      });

      if (response.data.success) {
        return {success: true};
      }

      return {success: false, error: response.data.error};
    } catch (error: any) {
      console.error('Password reset request error:', error);
      return {success: false, error: error.message || 'Failed to send reset code'};
    }
  }

  async verifyResetCode(email: string, code: string): Promise<{success: boolean; error?: string}> {
    try {
      const response = await axios.post(`${API_URL}/auth/verify-reset-code`, {
        email,
        code,
      });

      if (response.data.success) {
        return {success: true};
      }

      return {success: false, error: response.data.error};
    } catch (error: any) {
      console.error('Verify reset code error:', error);
      return {success: false, error: error.message || 'Invalid reset code'};
    }
  }

  async resetPassword(email: string, code: string, newPassword: string): Promise<{success: boolean; error?: string}> {
    try {
      const response = await axios.post(`${API_URL}/auth/reset-password`, {
        email,
        code,
        newPassword,
      });

      if (response.data.success) {
        return {success: true};
      }

      return {success: false, error: response.data.error};
    } catch (error: any) {
      console.error('Password reset error:', error);
      return {success: false, error: error.message || 'Failed to reset password'};
    }
  }
}

export const AuthService = new AuthServiceClass();
