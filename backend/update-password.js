const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'data', 'auth.db');
const db = new sqlite3.Database(dbPath);

const password = 'Nebula2025!';
const email = 'colinnebula@gmail.com';

bcrypt.hash(password, 10).then(hash => {
  console.log('Generated hash:', hash);
  
  db.run(
    'UPDATE users SET password_hash = ? WHERE email = ?',
    [hash, email],
    function(err) {
      if (err) {
        console.error('Error updating password:', err);
      } else {
        console.log(`✅ Password updated for ${email}`);
        console.log(`Rows changed: ${this.changes}`);
        
        // Verify the update
        db.get(
          'SELECT email, password_hash FROM users WHERE email = ?',
          [email],
          (err, row) => {
            if (err) {
              console.error('Error reading user:', err);
            } else if (row) {
              console.log('\nVerifying password...');
              bcrypt.compare(password, row.password_hash).then(match => {
                console.log('Password match:', match);
                if (match) {
                  console.log('\n✅ SUCCESS! Password is now correct!\n');
                } else {
                  console.log('\n❌ FAILED! Password still incorrect\n');
                }
                db.close();
              });
            }
          }
        );
      }
    }
  );
});
