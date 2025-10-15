const sqlite3 = require('sqlite3').verbose();
const bcryptjs = require('bcryptjs');

const db = new sqlite3.Database('../data/auth.db');

async function test() {
  // Get user
  db.get('SELECT * FROM users WHERE email = ?', ['colinnebula@gmail.com'], async (err, user) => {
    if (err) {
      console.error('❌ Database error:', err);
      db.close();
      return;
    }
    
    if (!user) {
      console.log('❌ User not found');
      db.close();
      return;
    }
    
    console.log('✅ User found:', user.email);
    console.log('   ID:', user.id);
    console.log('   Full name:', user.full_name);
    console.log('   Hash length:', user.password_hash.length);
    
    // Test password
    const testPassword = 'Nebula2025!';
    const isValid = await bcryptjs.compare(testPassword, user.password_hash);
    
    console.log('\n🔐 Password Test:');
    console.log('   Input:', testPassword);
    console.log('   Result:', isValid ? '✅ VALID' : '❌ INVALID');
    
    if (!isValid) {
      console.log('\n🔧 Updating password...');
      const newHash = await bcryptjs.hash(testPassword, 10);
      
      db.run('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, user.id], function(err) {
        if (err) {
          console.error('❌ Update failed:', err);
        } else {
          console.log('✅ Password updated!');
          console.log('   Changes:', this.changes);
        }
        db.close();
      });
    } else {
      console.log('\n✅ Password is already correct!');
      console.log('   Login should work with:');
      console.log('   Email: colinnebula@gmail.com');
      console.log('   Password: Nebula2025!');
      db.close();
    }
  });
}

test();
