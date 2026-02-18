import React, {useEffect, useState} from 'react';
import {StatusBar, useColorScheme} from 'expo-status-bar';
import {NavigationContainer} from '@react-navigation/native';
import {createStackNavigator} from '@react-navigation/stack';
import {Provider as PaperProvider, MD3DarkTheme, MD3LightTheme} from 'react-native-paper';
import {SafeAreaProvider} from 'react-native-safe-area-context';
import {AuthService} from './src/services/AuthService';
import {SocketService} from './src/services/SocketService';
import {ThemeProvider, useTheme} from './src/context/ThemeContext';

// Import screens and navigation
import LoginScreen from './src/screens/LoginScreen';
import ForgotPasswordScreen from './src/screens/ForgotPasswordScreen';
import PairingScreen from './src/screens/PairingScreen';
import RootNavigator from './src/navigation/RootNavigator';

const Stack = createStackNavigator();

function AppContent() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isPaired, setIsPaired] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const {isDark} = useTheme();

  useEffect(() => {
    checkAuth();
  }, []);

  // Add listener to check auth state periodically
  useEffect(() => {
    const interval = setInterval(async () => {
      const authenticated = await AuthService.isAuthenticated();
      if (!authenticated && isAuthenticated) {
        // User logged out - reset state
        setIsAuthenticated(false);
        setIsPaired(false);
      }
    }, 1000); // Check every second

    return () => clearInterval(interval);
  }, [isAuthenticated]);

  const checkAuth = async () => {
    try {
      const authenticated = await AuthService.isAuthenticated();
      setIsAuthenticated(authenticated);
      
      if (authenticated) {
        // HTTP API mode - no pairing needed
        // Initialize socket connection (disabled)
        // const token = await AuthService.getToken();
        // if (token) {
        //   SocketService.connect(token);
        // }
        // Skip pairing - HTTP API doesn't need it
        setIsPaired(true);
      }
    } catch (error) {
      console.error('Auth check error:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
    setIsPaired(true); // Skip pairing step
  };

  const handlePairingSuccess = () => {
    setIsPaired(true);
  };

  if (isLoading) {
    return null; // Or a loading screen component
  }

  // Use theme based on context
  const theme = isDark ? MD3DarkTheme : MD3LightTheme;

  return (
    <PaperProvider theme={theme}>
      <NavigationContainer>
        <Stack.Navigator
          screenOptions={{
            headerShown: false,
            cardStyle: {backgroundColor: theme.colors.background},
          }}>
          {!isAuthenticated ? (
            <>
              <Stack.Screen name="Login">
                {(props) => <LoginScreen {...props} onLoginSuccess={handleLoginSuccess} />}
              </Stack.Screen>
              <Stack.Screen 
                name="ForgotPassword" 
                component={ForgotPasswordScreen}
                options={{
                  headerShown: true,
                  title: 'Reset Password',
                  headerStyle: { backgroundColor: theme.colors.primary },
                  headerTintColor: '#fff',
                }}
              />
            </>
          ) : !isPaired ? (
            <Stack.Screen name="Pairing">
              {(props) => <PairingScreen {...props} onPairingSuccess={handlePairingSuccess} />}
            </Stack.Screen>
          ) : (
            <Stack.Screen name="Main" component={RootNavigator} />
          )}
        </Stack.Navigator>
        <StatusBar style={isDark ? 'light' : 'dark'} />
      </NavigationContainer>
    </PaperProvider>
  );
}

export default function App() {
  return (
    <SafeAreaProvider>
      <ThemeProvider>
        <AppContent />
      </ThemeProvider>
    </SafeAreaProvider>
  );
}
