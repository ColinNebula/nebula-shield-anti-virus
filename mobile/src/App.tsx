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
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';

// Screens
import DashboardScreen from './screens/DashboardScreen';
import DevicesScreen from './screens/DevicesScreen';
import ThreatsScreen from './screens/ThreatsScreen';
import SettingsScreen from './screens/SettingsScreen';

// Services
import {AuthService} from './services/AuthService';
import {SocketService} from './services/SocketService';

const Tab = createBottomTabNavigator();

function App(): JSX.Element {
  const isDarkMode = useColorScheme() === 'dark';
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const theme = isDarkMode ? MD3DarkTheme : MD3LightTheme;

  useEffect(() => {
    // Check if user is logged in
    AuthService.getToken().then(token => {
      if (token) {
        setIsAuthenticated(true);
        // Connect to WebSocket
        SocketService.connect(token);
      }
    });

    return () => {
      // Cleanup
      SocketService.disconnect();
    };
  }, []);

  return (
    <PaperProvider theme={theme}>
      <SafeAreaView style={styles.container}>
        <StatusBar
          barStyle={isDarkMode ? 'light-content' : 'dark-content'}
          backgroundColor={theme.colors.background}
        />
        <NavigationContainer>
          <Tab.Navigator
            screenOptions={({route}) => ({
              tabBarIcon: ({focused, color, size}) => {
                let iconName;

                if (route.name === 'Dashboard') {
                  iconName = focused ? 'view-dashboard' : 'view-dashboard-outline';
                } else if (route.name === 'Devices') {
                  iconName = focused ? 'devices' : 'devices';
                } else if (route.name === 'Threats') {
                  iconName = focused ? 'shield-alert' : 'shield-alert-outline';
                } else if (route.name === 'Settings') {
                  iconName = focused ? 'cog' : 'cog-outline';
                }

                return <Icon name={iconName} size={size} color={color} />;
              },
              tabBarActiveTintColor: '#00a8ff',
              tabBarInactiveTintColor: 'gray',
              tabBarStyle: {
                backgroundColor: theme.colors.surface,
                borderTopColor: theme.colors.outline,
              },
              headerStyle: {
                backgroundColor: theme.colors.surface,
              },
              headerTintColor: theme.colors.onSurface,
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
              name="Devices" 
              component={DevicesScreen}
              options={{title: 'My Devices'}}
            />
            <Tab.Screen 
              name="Threats" 
              component={ThreatsScreen}
              options={{title: 'Threats'}}
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

export default App;
