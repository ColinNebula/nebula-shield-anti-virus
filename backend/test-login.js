const axios = require('axios');
const bcrypt = require('bcryptjs');

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('🔐 TESTING LOGIN ENDPOINT');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

const email = 'colinnebula@gmail.com';
const password = 'Nebula2025!';

console.log('📧 Email:', email);
console.log('🔑 Password:', password);
console.log('🌐 Auth Server: http://localhost:8082\n');

// Test login
axios.post('http://localhost:8082/api/auth/login', {
  email: email,
  password: password
})
.then(response => {
  console.log('✅ LOGIN SUCCESSFUL!\n');
  console.log('Response:', JSON.stringify(response.data, null, 2));
  process.exit(0);
})
.catch(error => {
  console.log('❌ LOGIN FAILED!\n');
  
  if (error.response) {
    console.log('Status:', error.response.status);
    console.log('Error:', JSON.stringify(error.response.data, null, 2));
  } else if (error.request) {
    console.log('❌ NO RESPONSE from server');
    console.log('Server might not be running on port 8082');
  } else {
    console.log('Error:', error.message);
  }
  
  process.exit(1);
});
