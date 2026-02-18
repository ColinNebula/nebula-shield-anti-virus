/**
 * Mobile Scanner API Test Script
 * Tests all mobile scanner endpoints to verify functionality
 */

const axios = require('axios');

const API_URL = 'http://localhost:8080/api';

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[36m',
};

function log(color, message) {
  console.log(`${color}${message}${colors.reset}`);
}

async function testEndpoint(name, method, endpoint, data = null) {
  try {
    log(colors.blue, `\n🧪 Testing: ${name}`);
    log(colors.yellow, `   ${method.toUpperCase()} ${API_URL}${endpoint}`);
    
    let response;
    if (method === 'get') {
      response = await axios.get(`${API_URL}${endpoint}`);
    } else if (method === 'post') {
      response = await axios.post(`${API_URL}${endpoint}`, data);
    }
    
    log(colors.green, `   ✅ Success! Status: ${response.status}`);
    
    // Show relevant response data
    if (response.data) {
      if (response.data.success !== undefined) {
        log(colors.green, `   📊 Success: ${response.data.success}`);
      }
      if (response.data.isScanning !== undefined) {
        log(colors.green, `   🔍 Scanning: ${response.data.isScanning}`);
      }
      if (response.data.progress !== undefined) {
        log(colors.green, `   📈 Progress: ${response.data.progress}%`);
      }
      if (response.data.filesScanned !== undefined) {
        log(colors.green, `   📁 Files Scanned: ${response.data.filesScanned}`);
      }
      if (response.data.history) {
        log(colors.green, `   📜 History Count: ${response.data.history.length}`);
      }
    }
    
    return { success: true, data: response.data };
  } catch (error) {
    log(colors.red, `   ❌ Failed: ${error.message}`);
    if (error.response) {
      log(colors.red, `   📛 Status: ${error.response.status}`);
      log(colors.red, `   📛 Error: ${JSON.stringify(error.response.data)}`);
    }
    return { success: false, error: error.message };
  }
}

async function runTests() {
  log(colors.blue, '\n🚀 Starting Mobile Scanner API Tests...\n');
  log(colors.yellow, `🌐 API Base URL: ${API_URL}\n`);
  
  const results = {
    total: 0,
    passed: 0,
    failed: 0,
  };
  
  // Test 1: Get current scan status
  const test1 = await testEndpoint(
    'Get Scan Status',
    'get',
    '/scan/status'
  );
  results.total++;
  if (test1.success) results.passed++; else results.failed++;
  
  // Wait a bit before next test
  await new Promise(resolve => setTimeout(resolve, 500));
  
  // Test 2: Start a quick scan
  const test2 = await testEndpoint(
    'Start Quick Scan',
    'post',
    '/scan/quick',
    { path: 'C:\\Windows\\System32\\drivers' } // Smaller path for quick test
  );
  results.total++;
  if (test2.success) results.passed++; else results.failed++;
  
  // Wait for scan to start
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Test 3: Get scan status during scan
  const test3 = await testEndpoint(
    'Get Scan Status (During Scan)',
    'get',
    '/scan/status'
  );
  results.total++;
  if (test3.success) results.passed++; else results.failed++;
  
  // Wait a bit more
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  // Test 4: Get scan history
  const test4 = await testEndpoint(
    'Get Scan History',
    'get',
    '/scan/history'
  );
  results.total++;
  if (test4.success) results.passed++; else results.failed++;
  
  // Wait for scan to complete
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  // Test 5: Get scan results
  const test5 = await testEndpoint(
    'Get Scan Results',
    'get',
    '/scan/results'
  );
  results.total++;
  if (test5.success) results.passed++; else results.failed++;
  
  // Test 6: Get final scan status
  const test6 = await testEndpoint(
    'Get Final Scan Status',
    'get',
    '/scan/status'
  );
  results.total++;
  if (test6.success) results.passed++; else results.failed++;
  
  // Summary
  log(colors.blue, '\n' + '='.repeat(50));
  log(colors.blue, '📊 TEST SUMMARY');
  log(colors.blue, '='.repeat(50));
  log(colors.yellow, `   Total Tests: ${results.total}`);
  log(colors.green, `   ✅ Passed: ${results.passed}`);
  log(colors.red, `   ❌ Failed: ${results.failed}`);
  
  const successRate = ((results.passed / results.total) * 100).toFixed(1);
  if (results.failed === 0) {
    log(colors.green, `\n🎉 All tests passed! Mobile scanner is working correctly! (${successRate}%)`);
  } else {
    log(colors.yellow, `\n⚠️  Some tests failed. Success rate: ${successRate}%`);
  }
  
  log(colors.blue, '\n' + '='.repeat(50) + '\n');
}

// Run tests
runTests().catch(error => {
  log(colors.red, `\n💥 Test suite crashed: ${error.message}`);
  process.exit(1);
});
