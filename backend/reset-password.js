const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const db = new sqlite3.Database('../data/auth.db');

const newPassword = 'Nebula2025!';

bcrypt.hash(newPassword, 10, (err, hash) => {
  if (err) {
    console.error('Error hashing password:', err);
    return;
  }

  db.run(
    "UPDATE users SET password_hash=? WHERE id=1",
    [hash],
    function(err) {
      if (err) {
        console.error('Error updating password:', err);
      } else {
        console.log('\n✅ Password reset successful!\n');
        
        db.get(
          "SELECT email, full_name FROM users WHERE id=1",
          (err, row) => {
            if (row) {
              console.log('User:', row.full_name);
              console.log('Email:', row.email);
              console.log('Password:', newPassword);
              console.log('\n📝 Login at: http://localhost:3000/login\n');
            }
            db.close();
          }
        );
      }
    }
  );
});
