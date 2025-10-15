const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '..', 'data', 'auth.db');
const db = new sqlite3.Database(dbPath);

const email = 'colinnebula@gmail.com';
const newPassword = 'Nebula2025!';

console.log('\n🔐 Resetting Admin Password...\n');

// Generate new hash
bcrypt.hash(newPassword, 10, (err, hash) => {
  if (err) {
    console.error('❌ Error generating hash:', err);
    process.exit(1);
  }

  console.log('📝 New password:', newPassword);
  console.log('🔑 New hash:', hash);

  // Update database
  db.run(
    'UPDATE users SET password_hash = ? WHERE email = ?',
    [hash, email],
    function(err) {
      if (err) {
        console.error('❌ Error updating password:', err);
        process.exit(1);
      }

      console.log('✅ Password updated successfully!');

      // Verify the update
      db.get('SELECT email, password_hash FROM users WHERE email = ?', [email], (err, user) => {
        if (err) {
          console.error('❌ Error verifying update:', err);
        } else {
          console.log('\n📊 Updated user:', user.email);
          
          // Test the password
          bcrypt.compare(newPassword, user.password_hash, (err, match) => {
            if (err) {
              console.error('❌ Error testing password:', err);
            } else if (match) {
              console.log('✅ Password verification: SUCCESS');
              console.log('\n🎯 You can now login with:');
              console.log('   Email:', email);
              console.log('   Password:', newPassword);
            } else {
              console.error('❌ Password verification: FAILED');
            }
            
            db.close();
            process.exit(0);
          });
        }
      });
    }
  );
});
