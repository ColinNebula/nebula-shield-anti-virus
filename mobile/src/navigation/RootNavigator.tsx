import React from 'react';
import {createBottomTabNavigator} from '@react-navigation/bottom-tabs';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';

// Import screens
import DashboardScreen from '../screens/DashboardScreen';
import ThreatsScreen from '../screens/ThreatsScreen';
import ScansScreen from '../screens/ScansScreen';
import ToolsScreen from '../screens/ToolsScreen';
import NetworkTrafficScreen from '../screens/NetworkTrafficScreen';
import MobileProtectionScreen from '../screens/MobileProtectionScreen';
import SettingsScreen from '../screens/SettingsScreen';

const Tab = createBottomTabNavigator();

// Main tabs navigator
const RootNavigator = () => {
  return (
    <Tab.Navigator
      screenOptions={({route}) => ({
        tabBarIcon: ({focused, color, size}) => {
          let iconName: any;

          switch (route.name) {
            case 'Dashboard':
              iconName = 'view-dashboard';
              break;
            case 'Scans':
              iconName = 'shield-search';
              break;
            case 'Tools':
              iconName = 'toolbox';
              break;
            case 'Mobile':
              iconName = 'cellphone-check';
              break;
            case 'Network':
              iconName = 'network';
              break;
            case 'Settings':
              iconName = 'cog';
              break;
            default:
              iconName = 'circle';
          }

          return <Icon name={iconName} size={size} color={color} />;
        },
        tabBarActiveTintColor: '#2196f3',
        tabBarInactiveTintColor: '#999',
        tabBarStyle: {
          backgroundColor: '#fff',
          borderTopWidth: 1,
          borderTopColor: '#e0e0e0',
          paddingBottom: 5,
          paddingTop: 5,
          height: 60,
        },
        tabBarLabelStyle: {
          fontSize: 12,
          fontWeight: '600',
        },
        headerStyle: {
          backgroundColor: '#fff',
          elevation: 0,
          shadowOpacity: 0,
          borderBottomWidth: 1,
          borderBottomColor: '#e0e0e0',
        },
        headerTitleStyle: {
          fontWeight: 'bold',
          fontSize: 20,
        },
      })}>
      <Tab.Screen
        name="Dashboard"
        component={DashboardScreen}
        options={{
          headerTitle: 'Nebula Shield',
        }}
      />
      <Tab.Screen
        name="Scans"
        component={ScansScreen}
        options={{
          headerTitle: 'PC Scans',
        }}
      />
      <Tab.Screen
        name="Tools"
        component={ToolsScreen}
        options={{
          headerTitle: 'Security Tools',
        }}
      />
      <Tab.Screen
        name="Mobile"
        component={MobileProtectionScreen}
        options={{
          headerTitle: 'Phone Protection',
        }}
      />
      <Tab.Screen
        name="Network"
        component={NetworkTrafficScreen}
        options={{
          headerTitle: 'Network Traffic',
        }}
      />
      <Tab.Screen
        name="Settings"
        component={SettingsScreen}
      />
    </Tab.Navigator>
  );
};

export default RootNavigator;
