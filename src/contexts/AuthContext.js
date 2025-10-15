import React, { createContext, useState, useContext, useEffect } from 'react';
import axios from 'axios';

const AuthContext = createContext(null);

// Use relative URLs to go through the proxy configured in setupProxy.js
const AUTH_API_URL = '/api/auth';
const SUBSCRIPTION_API_URL = '/api/subscription';

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);
  const [subscription, setSubscription] = useState(null);

  // Verify token on mount
  useEffect(() => {
    if (token) {
      verifyToken();
    } else {
      setLoading(false);
    }
  }, [token]);

  // Load subscription info when user logs in
  useEffect(() => {
    if (user) {
      loadSubscription();
    }
  }, [user]);

  const verifyToken = async () => {
    try {
      // Check if it's a mock token from development mode
      if (token && token.startsWith('dev-token-')) {
        const mockUser = {
          id: 1,
          email: 'dev@nebulashield.com',
          name: 'Developer',
          role: 'admin',
          tier: 'premium'
        };
        setUser(mockUser);
        setLoading(false);
        return;
      }
      
      const response = await axios.get(`${AUTH_API_URL}/verify`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.data.success) {
        setUser(response.data.user);
      } else {
        logout();
      }
    } catch (error) {
      console.error('Token verification failed:', error);
      // If 404, it's development mode - keep the user logged in
      if (error.response?.status !== 404) {
        logout();
      }
    } finally {
      setLoading(false);
    }
  };

  const loadSubscription = async () => {
    try {
      const response = await axios.get(SUBSCRIPTION_API_URL, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.data.success) {
        setSubscription(response.data.subscription);
      }
    } catch (error) {
      console.error('Failed to load subscription:', error);
    }
  };

  const register = async (email, password, fullName, autoLogin = false) => {
    try {
      const response = await axios.post(`${AUTH_API_URL}/register`, {
        email,
        password,
        fullName
      });

      if (response.data.success) {
        // Only auto-login if explicitly requested (for email verification flow, we don't)
        if (autoLogin) {
          const { token: newToken, user: newUser } = response.data;
          setToken(newToken);
          setUser(newUser);
          localStorage.setItem('token', newToken);
        }
        return { success: true, message: response.data.message };
      }
      
      return { success: false, message: response.data.message };
    } catch (error) {
      // Development mode fallback - if auth endpoints don't exist (404), use mock auth
      if (error.response?.status === 404) {
        // In dev mode, still store user data locally without logging in
        // The verification system will be tested even in dev mode
        console.warn('⚠️ Using mock authentication - Auth endpoints not available in backend');
        return { success: true, message: 'Account created (Development Mode)' };
      }
      
      return { 
        success: false, 
        message: error.response?.data?.message || 'Registration failed' 
      };
    }
  };

  const login = async (email, password) => {
    try {
      const response = await axios.post(`${AUTH_API_URL}/login`, {
        email,
        password
      });

      if (response.data.success) {
        const { token: newToken, user: newUser } = response.data;
        setToken(newToken);
        setUser(newUser);
        localStorage.setItem('token', newToken);
        return { success: true, message: response.data.message || 'Login successful' };
      }
      
      return { success: false, message: response.data.message || 'Login failed' };
    } catch (error) {
      console.error('Login error:', error);
      
      // Development mode fallback - if auth endpoints don't exist (404), use mock auth
      if (error.response?.status === 404) {
        // Mock authentication for development
        const mockToken = 'dev-token-' + Date.now();
        const mockUser = {
          id: 1,
          email: email,
          name: email.split('@')[0],
          role: 'admin',
          tier: 'premium'
        };
        setToken(mockToken);
        setUser(mockUser);
        localStorage.setItem('token', mockToken);
        console.warn('⚠️ Using mock authentication - Auth endpoints not available in backend');
        return { success: true, message: 'Logged in (Development Mode)' };
      }
      
      if (error.code === 'ERR_NETWORK') {
        return { 
          success: false, 
          message: 'Cannot connect to server. Please make sure the backend is running on port 8080.' 
        };
      }
      
      if (error.response?.status === 401) {
        return { 
          success: false, 
          message: 'Invalid email or password' 
        };
      }
      
      return { 
        success: false, 
        message: error.response?.data?.message || error.message || 'Login failed. Please try again.' 
      };
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    setSubscription(null);
    localStorage.removeItem('token');
  };

  const checkFeatureAccess = async (feature) => {
    if (!token) return { hasAccess: false, requiresUpgrade: true };
    
    // Admins have access to all features
    if (user?.role === 'admin') {
      return { hasAccess: true, requiresUpgrade: false };
    }

    try {
      const response = await axios.post(
        `${SUBSCRIPTION_API_URL}/check-feature`,
        { feature },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      return response.data;
    } catch (error) {
      console.error('Feature check failed:', error);
      return { hasAccess: false, requiresUpgrade: true };
    }
  };

  const upgradeToPremium = async () => {
    try {
      const response = await axios.post(
        `${SUBSCRIPTION_API_URL}/upgrade`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (response.data.success) {
        setSubscription(response.data.subscription);
        // Update user tier
        setUser(prev => ({ ...prev, tier: 'premium' }));
        return { success: true, message: response.data.message };
      }
      
      return { success: false, message: 'Upgrade failed' };
    } catch (error) {
      return { 
        success: false, 
        message: error.response?.data?.message || 'Upgrade failed' 
      };
    }
  };

  const saveSettings = async (settings) => {
    if (!token) {
      console.log('saveSettings: No auth token, skipping user settings save');
      return { success: false, message: 'Not authenticated - settings will not persist across sessions' };
    }

    try {
      const response = await axios.put(
        '/api/settings',
        { settings },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      console.log('Settings saved successfully to auth server');
      return response.data;
    } catch (error) {
      console.error('Failed to save settings to auth server:', error);
      const errorMsg = error.response?.data?.message || error.message || 'Failed to save settings';
      return {
        success: false,
        message: errorMsg
      };
    }
  };

  const loadSettings = async () => {
    if (!token) return null;

    try {
      const response = await axios.get(
        '/api/settings',
        { headers: { Authorization: `Bearer ${token}` } }
      );

      return response.data.success ? response.data.settings : null;
    } catch (error) {
      console.error('Failed to load settings:', error);
      return null;
    }
  };

  const value = {
    user,
    token,
    loading,
    subscription,
    isAuthenticated: !!user,
    isPremium: user?.tier === 'premium' || user?.role === 'admin',
    isAdmin: user?.role === 'admin',
    register,
    login,
    logout,
    checkFeatureAccess,
    upgradeToPremium,
    saveSettings,
    loadSettings
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;
