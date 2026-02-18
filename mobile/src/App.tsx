import React, {useEffect, useState} from 'react';
import {
  SafeAreaView,
  StatusBar,
  StyleSheet,
  useColorScheme,
} from 'react-native';
import {NavigationContainer} from '@react-navigation/native';
import {createBottomTabNavigator} from '@react-navigation/bottom-tabs';
import {Provider as PaperProvider, MD3DarkTheme, MD3LightTheme} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';

// Screens
import DashboardScreen from './screens/DashboardScreen';
import ScansScreen from './screens/ScansScreen';
import ToolsScreen from './screens/ToolsScreen';
import WebProtectionScreen from './screens/WebProtectionScreen';
import NetworkMonitorScreen from './screens/NetworkMonitorScreen';
import SettingsScreen from './screens/SettingsScreen';

// Services
import {AuthService} from './services/AuthService';
import {SocketService} from './services/SocketService';

// Theme
import {ThemeProvider, useTheme} from './context/ThemeContext';

const Tab = createBottomTabNavigator();

function AppNavigator(): JSX.Element {
  const {isDark} = useTheme();
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const theme = isDark ? MD3DarkTheme : MD3LightTheme;
  
  console.log('AppNavigator: isDark =', isDark, ', theme =', theme.dark ? 'dark' : 'light');

  useEffect(() => {
    // Check if user is logged in
    AuthService.getToken().then(async token => {
      if (token) {
        setIsAuthenticated(true);
        // Connect to WebSocket for real-time updates
        try {
          await SocketService.connect(token);
          console.log('✅ WebSocket enabled for real-time updates');
        } catch (error) {
          console.error('❌ WebSocket connection failed:', error);
          console.log('📡 Falling back to HTTP polling');
        }
      }
    });

    return () => {
      // Cleanup
      SocketService.disconnect();
    };
  }, []);

  return (
    <PaperProvider theme={theme}>
      <SafeAreaView style={[styles.container, {backgroundColor: theme.colors.background}]}>
        <StatusBar
          barStyle={isDark ? 'light-content' : 'dark-content'}
          backgroundColor={theme.colors.background}
        />
        <NavigationContainer>
          <Tab.Navigator
            screenOptions={({route}) => ({
              tabBarIcon: ({focused, color, size}) => {
                let iconName;

                if (route.name === 'Dashboard') {
                  iconName = focused ? 'view-dashboard' : 'view-dashboard-outline';
                } else if (route.name === 'Scans') {
                  iconName = focused ? 'shield-search' : 'shield-search';
                } else if (route.name === 'Tools') {
                  iconName = focused ? 'toolbox' : 'toolbox-outline';
                } else if (route.name === 'Network') {
                  iconName = focused ? 'network' : 'network-outline';
                } else if (route.name === 'Settings') {
                  iconName = focused ? 'cog' : 'cog-outline';
                }

                return <Icon name={iconName} size={size} color={color} />;
              },
              tabBarActiveTintColor: '#00a8ff',
              tabBarInactiveTintColor: isDark ? '#999' : 'gray',
              tabBarStyle: {
                backgroundColor: theme.colors.surface,
                borderTopColor: theme.colors.outline,
                height: 60,
                paddingBottom: 8,
                paddingTop: 8,
              },
              tabBarLabelStyle: {
                fontSize: 12,
              },
              headerStyle: {
                backgroundColor: theme.colors.elevation.level2,
              },
              headerTintColor: theme.colors.onSurface,
              headerShadowVisible: false,
            })}>
            <Tab.Screen 
              name="Dashboard" 
              component={DashboardScreen}
              options={{
                title: 'Dashboard',
                headerTitle: '🛡️ Nebula Shield',
              }}
            />
            <Tab.Screen 
              name="Scans" 
              component={ScansScreen}
              options={{title: 'Scans'}}
            />
            <Tab.Screen 
              name="Tools" 
              component={ToolsScreen}
              options={{title: 'Tools'}}
            />
            <Tab.Screen 
              name="Network" 
              component={NetworkMonitorScreen}
              options={{title: 'Network'}}
            />
            <Tab.Screen 
              name="Settings" 
              component={SettingsScreen}
              options={{title: 'Settings'}}
            />
          </Tab.Navigator>
        </NavigationContainer>
      </SafeAreaView>
    </PaperProvider>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
});

function App(): JSX.Element {
  return (
    <ThemeProvider>
      <AppNavigator />
    </ThemeProvider>
  );
}

export default App;
