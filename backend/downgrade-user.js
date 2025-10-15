const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('../data/auth.db');

db.run(
  "UPDATE subscriptions SET tier='free', status='cancelled' WHERE user_id=1",
  function(err) {
    if (err) {
      console.error('Error:', err);
    } else {
      console.log('\n✅ Account downgraded to FREE tier\n');
      
      db.get(
        `SELECT u.email, u.full_name, s.tier, s.status 
         FROM users u 
         LEFT JOIN subscriptions s ON u.id = s.user_id 
         WHERE u.id=1`,
        (err, row) => {
          if (row) {
            console.log('User:', row.full_name);
            console.log('Email:', row.email);
            console.log('Tier:', row.tier);
            console.log('Status:', row.status);
            console.log('\n📝 Now LOGOUT and LOGIN again at http://localhost:3000/login');
            console.log('   Then go to: http://localhost:3000/premium');
            console.log('\n   You should see THREE payment buttons:\n');
            console.log('   1. 💳 Pay with Card (Stripe)');
            console.log('   2. P  Pay with PayPal');
            console.log('   3. Quick Upgrade (Demo)\n');
          }
          db.close();
        }
      );
    }
  }
);
