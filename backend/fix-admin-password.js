const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'data', 'auth.db');
const db = new sqlite3.Database(dbPath);

console.log('\n🔧 FIXING ADMIN PASSWORD\n');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

const email = 'colinnebula@gmail.com';
const newPassword = 'Nebula2025!';

console.log('📧 Email:', email);
console.log('🔑 New Password:', newPassword);
console.log('');

// First, check current state
db.get('SELECT id, email, password, role, tier, status FROM users WHERE email = ?', [email], async (err, user) => {
  if (err) {
    console.log('❌ Error:', err.message);
    db.close();
    return;
  }

  if (!user) {
    console.log('❌ User not found!');
    db.close();
    return;
  }

  console.log('📊 Current User State:');
  console.log('   ID:', user.id);
  console.log('   Email:', user.email);
  console.log('   Password:', user.password ? `${user.password.substring(0, 20)}...` : '❌ NULL/UNDEFINED');
  console.log('   Role:', user.role);
  console.log('   Tier:', user.tier);
  console.log('   Status:', user.status);
  console.log('');

  // Hash the new password
  console.log('🔐 Generating new password hash...');
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  console.log('✅ Hash generated:', hashedPassword.substring(0, 20) + '...');
  console.log('');

  // Update the password
  db.run(
    'UPDATE users SET password = ? WHERE email = ?',
    [hashedPassword, email],
    function(err) {
      if (err) {
        console.log('❌ Update failed:', err.message);
        db.close();
        return;
      }

      console.log('✅ Password updated successfully!');
      console.log('   Rows affected:', this.changes);
      console.log('');

      // Verify the update
      db.get('SELECT id, email, password, role, tier FROM users WHERE email = ?', [email], async (err, updatedUser) => {
        if (err) {
          console.log('❌ Verification failed:', err.message);
          db.close();
          return;
        }

        console.log('✅ Verification:');
        console.log('   Password field exists:', !!updatedUser.password);
        console.log('   Password hash:', updatedUser.password ? updatedUser.password.substring(0, 30) + '...' : 'NULL');
        console.log('');

        // Test the password
        const matches = await bcrypt.compare(newPassword, updatedUser.password);
        console.log('🔍 Password Test:');
        console.log('   Password matches:', matches ? '✅ YES' : '❌ NO');
        console.log('');

        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('🎯 CREDENTIALS:');
        console.log('   Email: colinnebula@gmail.com');
        console.log('   Password: Nebula2025!');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

        db.close();
      });
    }
  );
});
