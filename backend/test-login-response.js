const axios = require('axios');

console.log('\n🔍 TESTING LOGIN RESPONSE STRUCTURE\n');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

async function testLogin() {
  try {
    const response = await axios.post('http://localhost:8082/api/auth/login', {
      email: 'colinnebula@gmail.com',
      password: 'Nebula2025!'
    });

    console.log('✅ LOGIN SUCCESSFUL\n');
    console.log('📦 Full Response:');
    console.log(JSON.stringify(response.data, null, 2));
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    
    console.log('\n🔍 User Object Analysis:');
    const user = response.data.user;
    console.log('user.id:', user.id);
    console.log('user.email:', user.email);
    console.log('user.fullName:', user.fullName);
    console.log('user.tier:', user.tier);
    console.log('user.role:', user.role);
    console.log('\n🎯 Check Results:');
    console.log('isPremium (tier === "premium"):', user.tier === 'premium');
    console.log('isAdmin (role === "admin"):', user.role === 'admin');
    
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    
  } catch (error) {
    console.log('❌ LOGIN FAILED');
    console.log('Error:', error.response?.data || error.message);
  }
}

testLogin();
