import React, { createContext, useState, useContext, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';

const AuthContext = createContext(null);

// In development with React dev server, use proxy (relative URLs)
// In Electron or production, use direct backend URLs
const isElectron = typeof window !== 'undefined' && window.electronAPI?.isElectron;
const API_BASE = isElectron ? 'http://localhost:8080' : (import.meta.env.VITE_API_URL || '');
const AUTH_API_BASE = isElectron
  ? 'http://localhost:8082'
  : (import.meta.env.VITE_AUTH_API_URL || '');

const AUTH_API_URL = `${AUTH_API_BASE}/api/auth`;
const SUBSCRIPTION_API_URL = `${AUTH_API_BASE}/api/subscription`;

// Configure axios defaults for better error handling
axios.defaults.timeout = 10000; // 10 second timeout
axios.defaults.headers.common['Content-Type'] = 'application/json';

export const AuthProvider = ({ children }) => {
  useEffect(() => {
    console.log('[Auth] API bases:', {
      apiBase: API_BASE || '(relative)',
      authApiBase: AUTH_API_BASE
    });
  }, []);

  // Initialize from localStorage to persist across restarts
  const [user, setUser] = useState(() => {
    try {
      const savedUser = localStorage.getItem('user');
      return savedUser ? JSON.parse(savedUser) : null;
    } catch (error) {
      console.error('Failed to parse saved user:', error);
      return null;
    }
  });
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);
  const [isOnline, setIsOnline] = useState(true); // Track backend connectivity
  const [authServerDown, setAuthServerDown] = useState(false);
  const authDownToastShown = useRef(false);
  const [subscription, setSubscription] = useState(() => {
    try {
      const savedSubscription = localStorage.getItem('subscription');
      return savedSubscription ? JSON.parse(savedSubscription) : null;
    } catch (error) {
      console.error('Failed to parse saved subscription:', error);
      return null;
    }
  });

  // Verify token on mount (non-blocking)
  useEffect(() => {
    const initAuth = async () => {
      if (token) {
        // Set a timeout to prevent infinite loading
        const timeoutId = setTimeout(() => {
          console.warn('⏱️ Auth verification timeout - setting loading to false');
          setLoading(false);
        }, 3000);
        
        try {
          await verifyToken();
        } catch (error) {
          console.error('Auth init error:', error);
        } finally {
          clearTimeout(timeoutId);
        }
      } else {
        setLoading(false);
      }
    };
    
    initAuth();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  // Startup check for auth server availability
  useEffect(() => {
    if (typeof navigator !== 'undefined' && !navigator.onLine) {
      return;
    }

    const checkAuthServer = async () => {
      try {
        await axios.get(`${AUTH_API_BASE}/api/health`, { timeout: 3000 });
        setAuthServerDown(false);
        authDownToastShown.current = false;
      } catch (error) {
        if (!authDownToastShown.current) {
          authDownToastShown.current = true;
          setAuthServerDown(true);
          toast.error('Auth server not running. Start backend auth server on port 8082.', {
            duration: 6000
          });
        }
      }
    };

    checkAuthServer();
  }, []);

  // Retry token verification periodically when offline
  useEffect(() => {
    if (!isOnline && token && user) {
      console.log('📡 Backend offline - will retry verification every 30 seconds');
      const retryInterval = setInterval(async () => {
        console.log('🔄 Retrying token verification...');
        try {
          const response = await axios.get(`${AUTH_API_URL}/verify`, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: 5000
          });
          
          if (response.data.success) {
            console.log('✅ Backend is back online! Token verified.');
            setIsOnline(true);
            setUser(response.data.user);
            localStorage.setItem('user', JSON.stringify(response.data.user));
          }
        } catch (error) {
          console.log('⚠️ Backend still offline, will retry...');
        }
      }, 30000); // Retry every 30 seconds
      
      return () => clearInterval(retryInterval);
    }
  }, [isOnline, token, user]);

  // Load subscription info when user logs in
  useEffect(() => {
    if (user) {
      loadSubscription();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  const verifyToken = useCallback(async () => {
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
        // Persist mock user data to localStorage
        localStorage.setItem('user', JSON.stringify(mockUser));
        setLoading(false);
        return;
      }
      
      console.log('🔐 Verifying token...');
      console.log('API URL:', AUTH_API_URL);
      
      const response = await axios.get(`${AUTH_API_URL}/verify`, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 5000 // 5 second timeout to allow backend startup
      });
      
      if (response.data.success) {
        console.log('✅ Token verified, user:', response.data.user);
        setUser(response.data.user);
        setIsOnline(true); // Backend is available
        setAuthServerDown(false);
        authDownToastShown.current = false;
        // Persist user data to localStorage
        localStorage.setItem('user', JSON.stringify(response.data.user));
      } else {
        console.warn('❌ Token verification failed - invalid token');
        logout();
      }
    } catch (error) {
      console.error('❌ Token verification error:', error.code, error.message);
      // On network errors in production, retry a few times before logging out
      // This gives the backend time to start up
      if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND' || error.code === 'ERR_NETWORK' || error.message.includes('timeout')) {
        console.log('⚠️ Backend not available - this might be temporary during startup');
        setIsOnline(false); // Mark as offline
        if (!authDownToastShown.current) {
          authDownToastShown.current = true;
          setAuthServerDown(true);
          toast.error('Auth server not running. Start backend auth server on port 8082.', {
            duration: 6000
          });
        }
        // Keep user logged in with saved data from localStorage
        // User data was already loaded in state initialization
        if (user) {
          console.log('ℹ️ Using cached user data from localStorage, will retry verification when backend is available');
        } else {
          console.warn('⚠️ No cached user data available - user may need to login again');
        }
        // Don't logout - just mark as offline mode
      } else if (error.response?.status === 401 || error.response?.status === 403) {
        console.log('🚪 Logging out due to invalid/expired token');
        logout();
      } else {
        console.warn('⚠️ Token verification failed - keeping cached user data for offline access');
        setIsOnline(false);
      }
    } finally {
      setLoading(false);
    }
  }, [token]);

  const loadSubscription = useCallback(async () => {
    if (!token) return;
    
    try {
      const response = await axios.get(SUBSCRIPTION_API_URL, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 5000,
        // Suppress axios default error logging for 404s
        validateStatus: (status) => status < 500
      });
      
      // Only process if we got a successful response
      if (response.status === 200 && response.data.success) {
        setSubscription(response.data.subscription);
        // Persist subscription data to localStorage
        localStorage.setItem('subscription', JSON.stringify(response.data.subscription));
      }
    } catch (error) {
      // Silently fail if subscription endpoint doesn't exist or auth fails
      if (error.response?.status !== 404 && error.response?.status !== 401) {
        console.warn('Failed to load subscription:', error.message);
      }
    }
  }, [token]);

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
          localStorage.setItem('user', JSON.stringify(newUser));
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
      console.log('🔑 Attempting login for:', email);
      console.log('🌐 API URL:', `${AUTH_API_URL}/login`);
      
      // First, check if backend is accessible (with retry logic for Electron startup)
      if (isElectron) {
        let backendReady = false;
        const maxRetries = 5;
        
        for (let i = 0; i < maxRetries; i++) {
          try {
            await axios.get(`${API_BASE}/api/health`, { timeout: 2000 });
            backendReady = true;
            console.log('✅ Backend health check passed');
            break;
          } catch (err) {
            console.warn(`⏳ Backend not ready yet (attempt ${i + 1}/${maxRetries}), waiting...`);
            if (i < maxRetries - 1) {
              await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second
            }
          }
        }
        
        if (!backendReady) {
          return {
            success: false,
            message: 'Backend server is not responding. Please wait a moment and try again.'
          };
        }
      }
      
      const response = await axios.post(`${AUTH_API_URL}/login`, {
        email,
        password
      }, {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 15000 // 15 second timeout to handle backend startup delays
      });

      console.log('📡 Response received:', response.status, JSON.stringify(response.data, null, 2));

      if (response.data.success) {
        const { token: newToken, user: newUser } = response.data;
        console.log('✅ Login successful! Token:', newToken?.substring(0, 10) + '...', 'User:', newUser);
        setToken(newToken);
        setUser(newUser);
        localStorage.setItem('token', newToken);
        localStorage.setItem('user', JSON.stringify(newUser));
        console.log('💾 Token and user data stored in state and localStorage for persistent login');
        return { success: true, message: response.data.message || 'Login successful' };
      }
      
      return { success: false, message: response.data.message || 'Login failed' };
    } catch (error) {
      console.error('❌ Login error:', error);
      console.error('Error details:', {
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data,
        message: error.message,
        code: error.code,
        url: error.config?.url
      });
      
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
        localStorage.setItem('user', JSON.stringify(mockUser));
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
      
      if (error.response?.status === 403) {
        return { 
          success: false, 
          message: error.response?.data?.message || error.response?.data?.error || 'Access denied. Account may be locked or blocked for security.' 
        };
      }
      
      return { 
        success: false, 
        message: error.response?.data?.message || error.message || 'Login failed. Please try again.' 
      };
    }
  };

  const logout = () => {
    console.log('🚪 Logging out - clearing all persistent authentication data');
    setUser(null);
    setToken(null);
    setSubscription(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('subscription');
    console.log('✅ Logout complete - user must login again after restart');
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
        const updatedUser = { ...user, tier: 'premium' };
        setUser(updatedUser);
        // Persist updated data
        localStorage.setItem('user', JSON.stringify(updatedUser));
        localStorage.setItem('subscription', JSON.stringify(response.data.subscription));
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
    isOnline,
    authServerDown,
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
