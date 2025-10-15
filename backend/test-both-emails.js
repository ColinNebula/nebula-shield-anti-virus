const axios = require('axios');

console.log('\n🔍 TESTING BOTH EMAIL ADDRESSES\n');

const testLogins = [
  {
    name: 'Gmail Account (Should Work)',
    email: 'colinnebula@gmail.com',
    password: 'Nebula2025!'
  },
  {
    name: 'Nebula3ddev Account (Should FAIL)',
    email: 'colinnebula@nebula3ddev.com',
    password: 'Nebula2025!'
  }
];

async function testLogin(test) {
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`Testing: ${test.name}`);
  console.log(`Email: ${test.email}`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
  
  try {
    const response = await axios.post('http://localhost:8082/api/auth/login', {
      email: test.email,
      password: test.password
    });
    
    console.log('✅ LOGIN SUCCESSFUL');
    console.log('User:', response.data.user);
    console.log('');
    
    return true;
  } catch (error) {
    if (error.response) {
      console.log('❌ LOGIN FAILED');
      console.log('Status:', error.response.status);
      console.log('Message:', error.response.data.message);
      console.log('');
    } else {
      console.log('❌ ERROR:', error.message);
      console.log('');
    }
    
    return false;
  }
}

async function runTests() {
  for (const test of testLogins) {
    await testLogin(test);
  }
  
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📋 SUMMARY');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  console.log('Only colinnebula@gmail.com should work.');
  console.log('If nebula3ddev email works, there is a security issue!\n');
}

runTests();
