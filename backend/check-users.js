const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join('C:', 'Program Files', 'Nebula Shield', 'data', 'auth.db');
const db = new sqlite3.Database(dbPath);

console.log('\n=== CHECKING ALL USERS ===\n');

db.all(`
  SELECT u.id, u.email, u.full_name, u.password_hash, u.created_at, s.tier, s.status 
  FROM users u 
  LEFT JOIN subscriptions s ON u.id = s.user_id 
  ORDER BY u.id
`, [], async (err, rows) => {
  if (err) {
    console.error('Error:', err);
    db.close();
    process.exit(1);
  }

  if (rows.length === 0) {
    console.log('❌ No users found in database!');
    db.close();
    return;
  }

  console.log(`Found ${rows.length} user(s):\n`);
  
  for (const row of rows) {
    console.log('─────────────────────────────────');
    console.log(`ID: ${row.id}`);
    console.log(`Email: ${row.email}`);
    console.log(`Name: ${row.full_name}`);
    console.log(`Tier: ${row.tier || 'N/A'}`);
    console.log(`Status: ${row.status || 'N/A'}`);
    console.log(`Created: ${row.created_at}`);
    
    // Test password verification
    if (row.email === 'colinnebula@nebula3ddev.com') {
      console.log('\nTesting password: Nebula2025!');
      try {
        const isValid = await bcrypt.compare('Nebula2025!', row.password_hash);
        console.log(`Password valid: ${isValid ? '✅ YES' : '❌ NO'}`);
        
        if (!isValid) {
          console.log('\nHash in DB:', row.password_hash.substring(0, 30) + '...');
        }
      } catch (error) {
        console.log('Error testing password:', error.message);
      }
    }
    console.log('');
  }

  db.close();
});
