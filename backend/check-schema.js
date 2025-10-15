const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '..', 'data', 'auth.db');
const db = new sqlite3.Database(dbPath);

console.log('\n📊 DATABASE SCHEMA ANALYSIS\n');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

// Get users table schema
db.all("PRAGMA table_info(users)", [], (err, columns) => {
  if (err) {
    console.log('❌ Error:', err.message);
    db.close();
    return;
  }

  console.log('📋 USERS TABLE COLUMNS:\n');
  columns.forEach(col => {
    console.log(`   ${col.name.padEnd(20)} ${col.type.padEnd(15)} ${col.notnull ? 'NOT NULL' : ''} ${col.dflt_value ? `DEFAULT ${col.dflt_value}` : ''}`);
  });

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  // Get actual user data
  db.all('SELECT * FROM users WHERE email = ?', ['colinnebula@gmail.com'], (err, users) => {
    if (err) {
      console.log('❌ Error getting user:', err.message);
      db.close();
      return;
    }

    console.log('\n👤 ADMIN USER DATA:\n');
    if (users.length > 0) {
      const user = users[0];
      Object.keys(user).forEach(key => {
        const value = user[key];
        if (key.toLowerCase().includes('password') || key.toLowerCase().includes('hash')) {
          console.log(`   ${key.padEnd(20)} ${value ? value.substring(0, 30) + '...' : '❌ NULL'}`);
        } else {
          console.log(`   ${key.padEnd(20)} ${value || '(empty)'}`);
        }
      });
    } else {
      console.log('   ❌ No user found!');
    }

    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    db.close();
  });
});
