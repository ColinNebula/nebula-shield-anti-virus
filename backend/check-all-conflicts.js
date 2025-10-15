const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '..', 'data', 'auth.db');
const db = new sqlite3.Database(dbPath);

console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('🔍 COMPREHENSIVE CONFLICT CHECK');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// Check all users
db.all('SELECT * FROM users ORDER BY id', [], (err, users) => {
  if (err) {
    console.error('❌ Error reading users:', err);
    db.close();
    return;
  }

  console.log('📊 ALL USERS IN DATABASE:\n');
  users.forEach(u => {
    console.log(`┌─ User ID: ${u.id}`);
    console.log(`│  Email: ${u.email}`);
    console.log(`│  Name: ${u.name || u.full_name || 'N/A'}`);
    console.log(`│  Role: ${u.role || 'NOT SET'}`);
    console.log(`│  Tier: ${u.tier || 'NOT SET'}`);
    console.log(`│  Status: ${u.status || 'NOT SET'}`);
    console.log(`│  Password Hash: ${u.password_hash ? u.password_hash.substring(0, 20) + '...' : 'MISSING!'}`);
    console.log(`│  Created: ${u.created_at}`);
    console.log(`└─────────────────────────────────────\n`);
  });

  console.log(`📈 Total Users: ${users.length}\n`);

  // Check for duplicates
  const emails = users.map(u => u.email.toLowerCase());
  const duplicates = emails.filter((e, i) => emails.indexOf(e) !== i);
  
  if (duplicates.length > 0) {
    console.log('⚠️  DUPLICATE EMAILS FOUND:');
    duplicates.forEach(e => console.log(`   - ${e}`));
  } else {
    console.log('✅ No duplicate emails found');
  }

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  db.close();
});
