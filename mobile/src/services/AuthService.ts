import AsyncStorage from '@react-native-async-storage/async-storage';
import axios from 'axios';

const API_URL = 'http://localhost:3001/api';

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
}

export const AuthService = new AuthServiceClass();
