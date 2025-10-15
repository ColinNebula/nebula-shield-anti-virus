const axios = require('axios');

console.log('\n🔍 TESTING TOKEN VERIFY ENDPOINT\n');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

async function testVerify() {
  try {
    // First login to get a token
    console.log('Step 1: Logging in...\n');
    const loginResponse = await axios.post('http://localhost:8082/api/auth/login', {
      email: 'colinnebula@gmail.com',
      password: 'Nebula2025!'
    });

    const token = loginResponse.data.token;
    console.log('✅ Login successful');
    console.log('Token:', token.substring(0, 30) + '...\n');

    // Now verify the token
    console.log('Step 2: Verifying token...\n');
    const verifyResponse = await axios.get('http://localhost:8082/api/auth/verify', {
      headers: { Authorization: `Bearer ${token}` }
    });

    console.log('✅ Token verification successful\n');
    console.log('📦 Verify Response:');
    console.log(JSON.stringify(verifyResponse.data, null, 2));

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('\n🎯 User Data Check:');
    const user = verifyResponse.data.user;
    console.log('Email:', user.email);
    console.log('Tier:', user.tier, user.tier === 'premium' ? '✅' : '❌');
    console.log('Role:', user.role, user.role === 'admin' ? '✅' : '❌');
    console.log('\n🔍 Booleans:');
    console.log('isPremium:', user.tier === 'premium');
    console.log('isAdmin:', user.role === 'admin');
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

    if (user.role === 'admin' && user.tier === 'premium') {
      console.log('✅ VERIFY ENDPOINT IS WORKING CORRECTLY!');
      console.log('   Admin Panel should now be visible after refresh.\n');
    } else {
      console.log('❌ VERIFY ENDPOINT STILL HAS ISSUES!');
      console.log('   Expected role="admin" and tier="premium"\n');
    }

  } catch (error) {
    console.log('❌ ERROR');
    if (error.response) {
      console.log('Status:', error.response.status);
      console.log('Data:', error.response.data);
    } else {
      console.log('Error:', error.message);
    }
  }
}

testVerify();
