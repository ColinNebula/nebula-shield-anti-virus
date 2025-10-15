const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '..', 'data', 'auth.db');
const db = new sqlite3.Database(dbPath);

console.log('\n🔍 Searching for admin users...\n');

db.all(
  "SELECT id, email, role, tier, name, created_at FROM users WHERE email LIKE '%colin%' OR email LIKE '%nebula%' OR role = 'admin'",
  [],
  (err, users) => {
    if (err) {
      console.error('❌ Error:', err);
    } else {
      console.log('📧 Found users:\n');
      users.forEach(u => {
        console.log(`  ID: ${u.id}`);
        console.log(`  Email: ${u.email}`);
        console.log(`  Name: ${u.name || 'N/A'}`);
        console.log(`  Role: ${u.role || 'N/A'}`);
        console.log(`  Tier: ${u.tier || 'N/A'}`);
        console.log(`  Created: ${u.created_at}`);
        console.log('  ---');
      });
      
      console.log(`\n📊 Total found: ${users.length}\n`);
    }
    
    db.close();
  }
);
