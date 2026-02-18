import React from 'react';
import { View, Text } from 'react-native';

const TestBrowserScreen = () => {
  console.log('TestBrowserScreen rendering');
  
  return (
    <View style={{ backgroundColor: '#00FF00', padding: 50, margin: 20 }}>
      <Text style={{ fontSize: 30, fontWeight: 'bold', color: '#000' }}>
        ✅ TEST BROWSER SCREEN WORKS!
      </Text>
      <Text style={{ fontSize: 18, color: '#000', marginTop: 10 }}>
        This is a simple test component
      </Text>
    </View>
  );
};

export default TestBrowserScreen;
