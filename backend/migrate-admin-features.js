const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, '..', 'data', 'auth.db');
const db = new sqlite3.Database(dbPath);

console.log('🔄 Running database migration for admin features...\n');

db.serialize(() => {
  // Add role column to users table (if not exists)
  db.run(`
    ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'
  `, (err) => {
    if (err && !err.message.includes('duplicate column')) {
      console.error('❌ Error adding role column:', err);
    } else {
      console.log('✅ Added role column to users table');
    }
  });

  // Add status column to users table (if not exists)
  db.run(`
    ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'
  `, (err) => {
    if (err && !err.message.includes('duplicate column')) {
      console.error('❌ Error adding status column:', err);
    } else {
      console.log('✅ Added status column to users table');
    }
  });

  // Add tier column to users table (if not exists)
  db.run(`
    ALTER TABLE users ADD COLUMN tier TEXT DEFAULT 'free'
  `, (err) => {
    if (err && !err.message.includes('duplicate column')) {
      console.error('❌ Error adding tier column:', err);
    } else {
      console.log('✅ Added tier column to users table');
    }
  });

  // Add name column to users table (if not exists)
  db.run(`
    ALTER TABLE users ADD COLUMN name TEXT
  `, (err) => {
    if (err && !err.message.includes('duplicate column')) {
      console.error('❌ Error adding name column:', err);
    } else {
      console.log('✅ Added name column to users table');
    }
  });

  // Create audit_logs table
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      details TEXT,
      timestamp DATETIME NOT NULL,
      status TEXT DEFAULT 'success',
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )
  `, (err) => {
    if (err) {
      console.error('❌ Error creating audit_logs table:', err);
    } else {
      console.log('✅ Created audit_logs table');
    }
  });

  // Create scans table (for tracking user scans)
  db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      scan_type TEXT NOT NULL,
      started_at DATETIME NOT NULL,
      completed_at DATETIME,
      status TEXT DEFAULT 'in_progress',
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `, (err) => {
    if (err) {
      console.error('❌ Error creating scans table:', err);
    } else {
      console.log('✅ Created scans table');
    }
  });

  // Create scan_results table
  db.run(`
    CREATE TABLE IF NOT EXISTS scan_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER,
      file_path TEXT NOT NULL,
      threat_detected INTEGER DEFAULT 0,
      threat_name TEXT,
      timestamp DATETIME NOT NULL,
      FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )
  `, (err) => {
    if (err) {
      console.error('❌ Error creating scan_results table:', err);
    } else {
      console.log('✅ Created scan_results table');
    }
  });

  // Update existing users to have default values
  db.run(`
    UPDATE users 
    SET 
      role = COALESCE(role, 'user'),
      status = COALESCE(status, 'active'),
      tier = COALESCE(tier, 'free'),
      name = COALESCE(name, full_name)
    WHERE role IS NULL OR status IS NULL OR tier IS NULL OR name IS NULL
  `, (err) => {
    if (err) {
      console.error('❌ Error updating existing users:', err);
    } else {
      console.log('✅ Updated existing users with default values');
    }
  });

  // Set first user (colinnebula@gmail.com) as admin
  db.run(`
    UPDATE users 
    SET role = 'admin', tier = 'premium'
    WHERE email = 'colinnebula@gmail.com'
  `, (err) => {
    if (err) {
      console.error('❌ Error setting admin user:', err);
    } else {
      console.log('✅ Set colinnebula@gmail.com as admin with premium tier');
    }
  });

  // Insert sample audit log entries
  const sampleLogs = [
    ['colinnebula@gmail.com', 'DATABASE_MIGRATION', 'Admin features migration completed', new Date().toISOString().replace('T', ' ').substring(0, 19), 'success']
  ];

  db.get('SELECT id FROM users WHERE email = ?', ['colinnebula@gmail.com'], (err, user) => {
    if (!err && user) {
      const stmt = db.prepare('INSERT INTO audit_logs (user_id, action, details, timestamp, status) VALUES (?, ?, ?, ?, ?)');
      sampleLogs.forEach(log => {
        stmt.run(user.id, log[1], log[2], log[3], log[4]);
      });
      stmt.finalize((err) => {
        if (err) {
          console.error('❌ Error inserting sample logs:', err);
        } else {
          console.log('✅ Inserted sample audit logs');
        }
      });
    }
  });
});

// Close database after all operations
setTimeout(() => {
  db.close((err) => {
    if (err) {
      console.error('❌ Error closing database:', err);
    } else {
      console.log('\n✅ Migration completed successfully!');
      console.log('📊 Database ready for admin features\n');
    }
    process.exit(0);
  });
}, 1000);
