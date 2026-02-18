const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const db = new sqlite3.Database('./auth.db');

// Create tables
db.serialize(() => {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME
    )
  `);

  // Subscriptions table
  db.run(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      tier TEXT DEFAULT 'free',
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Create admin user
  const email = 'colinnebula@gmail.com';
  const password = 'NebulaShield2025!';
  const fullName = 'Colin Nebula';

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      db.close();
      return;
    }

    db.run(
      'INSERT OR REPLACE INTO users (email, password_hash, full_name, role) VALUES (?, ?, ?, ?)',
      [email, hash, fullName, 'admin'],
      function(err) {
        if (err) {
          console.error('Error creating user:', err);
        } else {
          console.log(`\n✅ Database initialized!`);
          console.log(`✅ Admin user created!`);
          console.log(`\nYour credentials:`);
          console.log(`  📧 Email: ${email}`);
          console.log(`  🔑 Password: ${password}\n`);

          // Create subscription for user
          db.run(
            'INSERT OR REPLACE INTO subscriptions (user_id, tier, status) VALUES (?, ?, ?)',
            [this.lastID, 'free', 'active']
          );
        }
        db.close();
      }
    );
  });
});
