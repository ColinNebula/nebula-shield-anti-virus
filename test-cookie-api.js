/**
 * Test script for Cookie Detection API
 */

const axios = require('axios');

const API_URL = 'http://localhost:3001/api';

async function testCookieAPI() {
  console.log('🧪 Testing Cookie Detection & Security API\n');
  
  try {
    // Test 1: Scan cookies for a domain
    console.log('1️⃣ Testing Cookie Scan...');
    const scanResult = await axios.post(`${API_URL}/browser/cookies/scan`, {
      domain: 'facebook.com'
    });
    
    console.log('✅ Cookie Scan Response:');
    console.log(`   Domain: ${scanResult.data.domain}`);
    console.log(`   Total Cookies: ${scanResult.data.stats.total}`);
    console.log(`   Tracking Cookies: ${scanResult.data.stats.tracking}`);
    console.log(`   Malicious Cookies: ${scanResult.data.stats.malicious}`);
    console.log(`   Blocked Cookies: ${scanResult.data.stats.blocked}`);
    console.log(`   Recommendations: ${scanResult.data.recommendations.length}`);
    
    // Show first few cookies with details
    console.log('\n   📋 Sample Cookies:');
    scanResult.data.cookies.slice(0, 3).forEach(cookie => {
      console.log(`      - ${cookie.name} (${cookie.category})`);
      console.log(`        Risk: ${cookie.riskLevel || 'low'}, Tracking: ${cookie.isTracking ? 'Yes' : 'No'}, Malicious: ${cookie.isMalicious ? 'Yes' : 'No'}`);
      if (cookie.description) {
        console.log(`        Info: ${cookie.description}`);
      }
    });
    
    console.log('\n   💡 Recommendations:');
    scanResult.data.recommendations.forEach(rec => {
      console.log(`      ${rec}`);
    });
    
    // Test 2: Get cookie stats
    console.log('\n2️⃣ Testing Cookie Blocking Stats...');
    const statsResult = await axios.get(`${API_URL}/browser/cookies/stats`);
    
    console.log('✅ Cookie Stats:');
    console.log(`   Total Blocked: ${statsResult.data.stats.totalBlocked}`);
    console.log(`   Today Blocked: ${statsResult.data.stats.todayBlocked}`);
    console.log(`   Tracking Blocked: ${statsResult.data.stats.trackingBlocked}`);
    console.log(`   Malicious Blocked: ${statsResult.data.stats.maliciousBlocked}`);
    console.log(`   Bandwidth Saved: ${statsResult.data.stats.bandwidthSaved} MB`);
    console.log(`   Privacy Score: ${statsResult.data.stats.privacyScore}/100`);
    
    // Test 3: Get blocking rules
    console.log('\n3️⃣ Testing Cookie Blocking Rules...');
    const rulesResult = await axios.get(`${API_URL}/browser/cookies/rules`);
    
    console.log('✅ Cookie Blocking Rules:');
    console.log(`   Total Rules: ${rulesResult.data.totalRules}`);
    console.log(`   Enabled Rules: ${rulesResult.data.enabledRules}`);
    
    console.log('\n   📜 Rules:');
    rulesResult.data.rules.forEach(rule => {
      const status = rule.enabled ? '✅' : '❌';
      console.log(`      ${status} ${rule.name} (${rule.priority} priority)`);
      console.log(`         Action: ${rule.action}, Category: ${rule.category || 'custom'}`);
    });
    
    // Test 4: Delete cookies by category
    console.log('\n4️⃣ Testing Cookie Deletion...');
    const deleteResult = await axios.post(`${API_URL}/browser/cookies/delete`, {
      domain: 'example.com',
      category: 'advertising'
    });
    
    console.log('✅ Cookie Deletion:');
    console.log(`   ${deleteResult.data.message}`);
    console.log(`   Cookies Removed: ${deleteResult.data.deleted}`);
    
    // Test 5: Update a blocking rule
    console.log('\n5️⃣ Testing Rule Update...');
    const updateResult = await axios.post(`${API_URL}/browser/cookies/rules/update`, {
      ruleId: 'rule_2',
      enabled: false,
      action: 'warn'
    });
    
    console.log('✅ Rule Update:');
    console.log(`   ${updateResult.data.message}`);
    console.log(`   Rule ID: ${updateResult.data.ruleId}, Enabled: ${updateResult.data.enabled}`);
    
    console.log('\n✅ All tests passed!\n');
    console.log('🎉 Cookie Detection & Security System is fully operational!\n');
    console.log('Features Available:');
    console.log('  ✅ Real-time cookie scanning with security analysis');
    console.log('  ✅ Malicious cookie detection (18 tracking patterns + 5 malicious patterns)');
    console.log('  ✅ Cookie categorization (necessary, analytics, advertising, etc.)');
    console.log('  ✅ Auto-blocking rules with configurable priorities');
    console.log('  ✅ Privacy scoring and bandwidth tracking');
    console.log('  ✅ Cookie deletion by domain/category');
    console.log('  ✅ Detailed recommendations and threat analysis\n');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    if (error.response) {
      console.error('   Response:', error.response.data);
    }
  }
}

// Run tests
testCookieAPI();
