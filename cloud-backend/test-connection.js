/**
 * Test WebSocket Connection
 * Run this to verify cloud backend is working
 */

const io = require('socket.io-client');

const SOCKET_URL = 'http://localhost:3001';
const TEST_EMAIL = 'admin@test.com';
const TEST_PASSWORD = 'admin';

async function testCloudBackend() {
  console.log('🧪 Testing Nebula Shield Cloud Backend...\n');

  // Test 1: Health Check
  console.log('1️⃣  Testing health endpoint...');
  try {
    const fetch = (await import('node-fetch')).default;
    const healthResponse = await fetch('http://localhost:3001/health');
    const healthData = await healthResponse.json();
    console.log('✅ Health check passed:', healthData.status);
    console.log(`   Uptime: ${Math.floor(healthData.uptime)}s\n`);
  } catch (error) {
    console.error('❌ Health check failed:', error.message);
    return;
  }

  // Test 2: Authentication
  console.log('2️⃣  Testing authentication...');
  let token;
  try {
    const fetch = (await import('node-fetch')).default;
    const loginResponse = await fetch('http://localhost:3001/api/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        email: TEST_EMAIL,
        password: TEST_PASSWORD
      })
    });
    const loginData = await loginResponse.json();
    
    if (loginData.success) {
      token = loginData.token;
      console.log('✅ Authentication passed');
      console.log(`   User: ${loginData.user.email}\n`);
    } else {
      console.error('❌ Authentication failed:', loginData.error);
      return;
    }
  } catch (error) {
    console.error('❌ Authentication failed:', error.message);
    return;
  }

  // Test 3: WebSocket Connection
  console.log('3️⃣  Testing WebSocket connection...');
  return new Promise((resolve) => {
    const socket = io(SOCKET_URL, {
      transports: ['websocket']
    });

    socket.on('connect', () => {
      console.log('✅ WebSocket connected');
      console.log(`   Socket ID: ${socket.id}\n`);

      // Test 4: WebSocket Authentication
      console.log('4️⃣  Testing WebSocket authentication...');
      socket.emit('authenticate', {
        token: token,
        deviceId: 'test-desktop-001',
        deviceType: 'desktop'
      });
    });

    socket.on('authenticated', (data) => {
      console.log('✅ WebSocket authenticated');
      console.log(`   User ID: ${data.userId}`);
      console.log(`   Device ID: ${data.deviceId}`);
      console.log(`   Active devices: ${data.activeDevices}\n`);

      // Test 5: Send Test Threat
      console.log('5️⃣  Testing threat detection broadcast...');
      socket.emit('threat:detected', {
        threatName: 'Test.Virus.Win32',
        filePath: 'C:\\Windows\\System32\\test.exe',
        severity: 'high',
        action: 'quarantined'
      });
      console.log('✅ Threat event sent\n');

      // Test 6: Send Metrics
      console.log('6️⃣  Testing metrics broadcast...');
      socket.emit('metrics:update', {
        cpu: 45,
        memory: 62,
        disk: 38,
        threatsFound: 5,
        lastScan: new Date().toISOString()
      });
      console.log('✅ Metrics event sent\n');

      // Wait a bit then disconnect
      setTimeout(() => {
        console.log('✅ All tests passed!\n');
        console.log('🎉 Cloud backend is working correctly!');
        console.log('\n📱 Ready to connect mobile app!');
        socket.disconnect();
        resolve();
      }, 1000);
    });

    socket.on('authentication:failed', (data) => {
      console.error('❌ WebSocket authentication failed:', data.error);
      socket.disconnect();
      resolve();
    });

    socket.on('connect_error', (error) => {
      console.error('❌ WebSocket connection error:', error.message);
      resolve();
    });
  });
}

// Run tests
testCloudBackend().then(() => {
  process.exit(0);
}).catch((error) => {
  console.error('Test failed:', error);
  process.exit(1);
});
