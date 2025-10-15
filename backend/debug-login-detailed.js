const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

console.log('\n🔍 DETAILED LOGIN DEBUG\n');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

// Test credentials
const testEmail = 'colinnebula@gmail.com';
const testPassword = 'Nebula2025!';

console.log(`📧 Testing Email: ${testEmail}`);
console.log(`🔑 Testing Password: ${testPassword}`);
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Step 1: Check database directly
const dbPath = path.join(__dirname, '..', 'data', 'auth.db');
const db = new sqlite3.Database(dbPath);

db.get('SELECT * FROM users WHERE email = ?', [testEmail], async (err, user) => {
  if (err) {
    console.log('❌ DATABASE ERROR:', err.message);
    db.close();
    return;
  }

  console.log('📊 STEP 1: Database Check');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  if (!user) {
    console.log('❌ User not found in database!');
    db.close();
    return;
  }

  console.log('✅ User found in database');
  console.log('User ID:', user.id);
  console.log('Email:', user.email);
  console.log('Name:', user.name || user.fullName || 'N/A');
  console.log('Role:', user.role);
  console.log('Tier:', user.tier);
  console.log('Status:', user.status);
  console.log('Password Hash:', user.password.substring(0, 20) + '...');
  console.log('');

  // Step 2: Test password hash
  console.log('🔐 STEP 2: Password Verification');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  const passwordMatch = await bcrypt.compare(testPassword, user.password);
  
  if (passwordMatch) {
    console.log('✅ Password matches hash in database');
  } else {
    console.log('❌ Password does NOT match hash');
    console.log('   This means the password in database is different!');
  }
  console.log('');

  db.close();

  // Step 3: Test API endpoint
  console.log('🌐 STEP 3: API Login Test');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('Sending POST to: http://localhost:8082/api/auth/login');
  console.log('');

  try {
    const response = await axios.post('http://localhost:8082/api/auth/login', {
      email: testEmail,
      password: testPassword
    });

    console.log('✅ API LOGIN SUCCESSFUL');
    console.log('Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
  } catch (error) {
    if (error.response) {
      console.log('❌ API LOGIN FAILED');
      console.log('Status:', error.response.status);
      console.log('Message:', error.response.data.message || error.response.data);
      console.log('');
      console.log('Full Response:', JSON.stringify(error.response.data, null, 2));
    } else if (error.request) {
      console.log('❌ NO RESPONSE FROM SERVER');
      console.log('Error:', error.message);
      console.log('The auth server may not be running or not accessible');
    } else {
      console.log('❌ REQUEST ERROR:', error.message);
    }
  }

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🏁 DEBUG COMPLETE');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});
